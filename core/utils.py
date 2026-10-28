import ctypes
from ctypes import wintypes
import os
import subprocess
from typing import Callable, Optional

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_PINNED = 0x00080000
FILE_ATTRIBUTE_UNPINNED = 0x00100000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000

CLOUD_OR_SPARSE_MASK = (
    FILE_ATTRIBUTE_SPARSE_FILE
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)


class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("i64Size", ctypes.c_longlong),
        ("i64NumItems", ctypes.c_longlong),
    ]


def expand_home(path: str) -> str:
    """Expands '~' and Windows environment variables (%LOCALAPPDATA%, %APPDATA%, etc.)."""
    expanded = os.path.expandvars(os.path.expanduser(path))
    return os.path.normpath(expanded)


def abbreviate_path(path: str) -> str:
    """Replaces the user's home directory prefix with '~' for clean UI display."""
    norm_path = os.path.normpath(path)
    home = os.path.normpath(os.path.expanduser("~"))
    if norm_path.lower().startswith(home.lower()):
        return "~" + norm_path[len(home):]
    return norm_path


def format_size(size_bytes: int) -> str:
    """Formats bytes into human-readable KB, MB, or GB strings."""
    if size_bytes <= 0:
        return "0 B"
    gb = size_bytes / (1024 ** 3)
    if gb >= 1.0:
        return f"{gb:.2f} GB"
    mb = size_bytes / (1024 ** 2)
    if mb >= 0.1:
        return f"{mb:.1f} MB"
    kb = size_bytes / 1024
    if kb >= 1.0:
        return f"{kb:.0f} KB"
    return f"{size_bytes} B"


def _get_ntfs_physical_file_size(path: str, st: os.stat_result) -> int:
    """Returns real physical bytes allocated on NTFS (`GetCompressedFileSizeW`).
    
    Crucial on Windows because sparse files like WSL2/Docker `ext4.vhdx` or OneDrive
    cloud-only files report huge logical `st_size` while physically consuming much less (or 0 B) on SSD.
    """
    attrs = getattr(st, "st_file_attributes", 0)
    # If it's a cloud placeholder (OneDrive online-only), it occupies 0 physical bytes locally
    if attrs & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_OFFLINE):
        return 0

    if os.name == "nt" and ((attrs & FILE_ATTRIBUTE_SPARSE_FILE) or st.st_size >= 32 * 1024 * 1024):
        try:
            high_dword = wintypes.DWORD(0)
            low_dword = ctypes.windll.kernel32.GetCompressedFileSizeW(
                ctypes.c_wchar_p(path), ctypes.byref(high_dword)
            )
            if low_dword != 0xFFFFFFFF or ctypes.GetLastError() == 0:
                return (high_dword.value << 32) + low_dword
        except Exception:
            pass
    return st.st_size


def fast_dir_size(path: str, cancel_check: Optional[Callable[[], bool]] = None) -> int:
    """Recursively calculates real physical directory size on NTFS disk using os.scandir.
    
    Skips NTFS junctions/reparse points to avoid infinite loops or double-counting,
    and uses `GetCompressedFileSizeW` for sparse/large files (e.g. Docker/WSL2 .vhdx).
    Silently ignores PermissionError, FileNotFoundError, and OSError.
    """
    total = 0
    stack = [path]
    while stack:
        if cancel_check and cancel_check():
            break
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        st = entry.stat(follow_symlinks=False)
                        attrs = getattr(st, "st_file_attributes", 0)
                        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += _get_ntfs_physical_file_size(entry.path, st)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return total


def get_entry_size(path: str, cancel_check: Optional[Callable[[], bool]] = None) -> int:
    """Gets real physical size on disk of either a file or directory safely."""
    try:
        if os.path.islink(path):
            return 0
        if os.path.isfile(path):
            st = os.stat(path, follow_symlinks=False)
            return _get_ntfs_physical_file_size(path, st)
        if os.path.isdir(path):
            return fast_dir_size(path, cancel_check)
    except (PermissionError, FileNotFoundError, OSError):
        return 0
    return 0


def get_windows_trash_size() -> int:
    """Calculates the current physical size of the Windows Recycle Bin via SHQueryRecycleBinW."""
    if os.name != "nt":
        return 0
    try:
        rb_info = _SHQUERYRBINFO()
        rb_info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
        # Passing None queries the aggregated Recycle Bin across all local drives
        res = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(rb_info))
        if res == 0 and rb_info.i64Size >= 0:
            return int(rb_info.i64Size)
    except Exception:
        pass
    return 0


def open_windows_trash() -> None:
    """Opens the Windows Recycle Bin in File Explorer."""
    try:
        subprocess.Popen(
            ["explorer.exe", "shell:RecycleBinFolder"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def empty_windows_trash() -> tuple[bool, str]:
    """Empties the Windows Recycle Bin safely using SHEmptyRecycleBinW."""
    if os.name != "nt":
        return False, "Función disponible solo en Windows."

    if get_windows_trash_size() == 0:
        return True, "La Papelera de reciclaje ya está vacía."

    # Flags: SHERB_NOCONFIRMATION (0x1) | SHERB_NOPROGRESSUI (0x2) | SHERB_NOSOUND (0x4) = 0x7
    try:
        res = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x00000007)
        if res == 0 or get_windows_trash_size() == 0:
            return (
                True,
                "Papelera de reciclaje vaciada correctamente. El espacio ya está libre en tu disco NTFS.",
            )
    except Exception:
        pass

    # Fallback via PowerShell Clear-RecycleBin
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=CREATE_NO_WINDOW,
            check=False,
        )
        if proc.returncode == 0 or get_windows_trash_size() == 0:
            return (
                True,
                "Papelera de reciclaje vaciada correctamente. El espacio ya está libre en tu disco NTFS.",
            )
    except Exception:
        pass

    return False, "No se pudo vaciar por completo la Papelera (algún archivo podría estar en uso)."


def trim_background_working_sets() -> int:
    """Uses Windows API EmptyWorkingSet (K32EmptyWorkingSet) on accessible user processes
    to return unused/idle RAM pages back to the system immediately without closing any app.
    Returns the number of processes trimmed.
    """
    if os.name != "nt":
        return 0

    trimmed_count = 0
    my_pid = os.getpid()
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_SET_QUOTA = 0x0100

    try:
        import psutil
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi

        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info.get("pid")
            if not pid or pid == my_pid or pid <= 4:
                continue
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid)
            if handle:
                try:
                    if psapi.EmptyWorkingSet(handle):
                        trimmed_count += 1
                except Exception:
                    pass
                finally:
                    kernel32.CloseHandle(handle)
    except Exception:
        pass

    return trimmed_count


def run_quick_windows_optimizations() -> str:
    """Runs safe user-level Windows optimizations:
    1. Flushes local Windows DNS cache (`ipconfig /flushdns`)
    2. Purges unlocked Explorer thumbnail cache files (`thumbcache_*.db`)
    3. Trims idle working set pages in RAM (`EmptyWorkingSet`)
    """
    messages: list[str] = []

    # 1. Flush Windows DNS Cache
    try:
        subprocess.run(
            ["ipconfig", "/flushdns"],
            capture_output=True,
            text=True,
            timeout=6,
            creationflags=CREATE_NO_WINDOW,
            check=False,
        )
        messages.append("Caché DNS limpiada")
    except Exception:
        pass

    # 2. Clean unlocked Explorer thumbcache_*.db files
    explorer_cache_dir = expand_home(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer")
    cleaned_thumbs = 0
    if os.path.isdir(explorer_cache_dir):
        try:
            with os.scandir(explorer_cache_dir) as it:
                for entry in it:
                    if entry.name.lower().startswith("thumbcache_") and entry.name.lower().endswith(".db"):
                        try:
                            os.unlink(entry.path)
                            cleaned_thumbs += 1
                        except OSError:
                            # Active thumbcache files locked by explorer.exe are safely skipped
                            continue
        except Exception:
            pass
    if cleaned_thumbs > 0:
        messages.append(f"Miniaturas de Explorer regeneradas ({cleaned_thumbs})")

    # 3. Trim RAM Working Sets across idle processes
    trimmed = trim_background_working_sets()
    if trimmed > 0:
        messages.append(f"Working Sets de RAM compactados ({trimmed} proc.)")

    if not messages:
        return "✓ Optimizaciones de Windows ejecutadas."
    return "✓ " + " • ".join(messages) + "."


def reveal_in_explorer(path: str) -> None:
    """Opens Windows File Explorer and highlights the target file or folder using `explorer /select,`."""
    try:
        norm = os.path.normpath(path)
        if os.path.exists(norm):
            subprocess.Popen(
                ["explorer.exe", f"/select,{norm}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass
