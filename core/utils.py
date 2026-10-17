import os
import shutil
import subprocess
from typing import Callable, Optional


def expand_home(path: str) -> str:
    """Expands '~' to the active user's home directory."""
    return os.path.expanduser(path)


def abbreviate_path(path: str) -> str:
    """Replaces the user's home directory prefix with '~' for clean UI display."""
    home = os.path.expanduser("~")
    if path.startswith(home):
        return "~" + path[len(home):]
    return path


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


def _stat_physical_bytes(st: os.stat_result) -> int:
    """Returns real physical bytes allocated on APFS (`st_blocks * 512`) when available.
    
    Crucial on macOS because sparse files like `Docker.raw` report 60 GB logical `st_size`
    while physically consuming only ~7.4 GB on disk.
    """
    blocks = getattr(st, "st_blocks", None)
    if blocks is not None and blocks >= 0:
        physical = blocks * 512
        if physical == 0 and st.st_size > 0 and st.st_size <= 4096:
            return st.st_size
        return physical
    return st.st_size


def fast_dir_size(path: str, cancel_check: Optional[Callable[[], bool]] = None) -> int:
    """Recursively calculates real physical directory size on disk using os.scandir.
    
    Tracks seen inodes (`st_ino`) to avoid double-counting hard links and uses
    `st_blocks * 512` to report accurate APFS physical space.
    Silently ignores PermissionError, FileNotFoundError, and OSError (SIP protected files).
    """
    total = 0
    seen_inodes: set[int] = set()
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
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            if st.st_nlink > 1:
                                if st.st_ino in seen_inodes:
                                    continue
                                seen_inodes.add(st.st_ino)
                            total += _stat_physical_bytes(st)
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
            return _stat_physical_bytes(st)
        if os.path.isdir(path):
            return fast_dir_size(path, cancel_check)
    except (PermissionError, FileNotFoundError, OSError):
        return 0
    return 0


def get_macos_trash_size() -> int:
    """Calculates the current physical size of ~/.Trash."""
    trash_dir = expand_home("~/.Trash")
    if not os.path.isdir(trash_dir):
        return 0
    return fast_dir_size(trash_dir)


def open_macos_trash() -> None:
    """Opens the user's macOS Trash folder in Finder."""
    trash_dir = expand_home("~/.Trash")
    try:
        subprocess.Popen(
            ["open", trash_dir],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def empty_macos_trash() -> tuple[bool, str]:
    """Empties the user's macOS Trash safely.
    
    First attempts Finder AppleScript so Finder updates its Trash icon immediately;
    falls back to removing children inside ~/.Trash directly.
    """
    trash_dir = expand_home("~/.Trash")
    if not os.path.isdir(trash_dir):
        return True, "La Papelera ya está vacía."

    # Attempt via Finder AppleScript first (non-blocking if permissions allow)
    try:
        proc = subprocess.run(
            ["osascript", "-e", 'tell application "Finder" to empty the trash'],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0 and get_macos_trash_size() == 0:
            return True, "Papelera vaciada correctamente. El espacio ya está libre en tu disco APFS."
    except Exception:
        pass

    # Fallback: directly delete contents inside ~/.Trash (never ~/.Trash itself)
    errors = 0
    try:
        with os.scandir(trash_dir) as it:
            entries = list(it)
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path, ignore_errors=False)
                else:
                    os.unlink(entry.path)
            except Exception:
                errors += 1
    except (PermissionError, FileNotFoundError, OSError):
        return False, "No se pudo acceder a ~/.Trash (revisa permisos de Acceso Total al Disco)."

    if errors == 0:
        return True, "Papelera vaciada correctamente. El espacio ya está libre en tu disco APFS."
    return True, f"Papelera vaciada ({errors} elemento(s) en uso fueron omitidos)."


def run_quick_macos_optimizations() -> str:
    """Runs safe user-level macOS optimizations:
    1. Disables orphaned background updaters in launchctl (Microsoft AutoUpdate, OneDrive, Zoom)
    2. Resets QuickLook thumbnail cache (`qlmanage -r cache`)
    3. Flushes local user DNS cache (`dscacheutil -flushcache`)
    """
    messages: list[str] = []
    uid = os.getuid()
    orphan_services = [
        "com.microsoft.update.agent",
        "com.microsoft.SyncReporter",
        "com.microsoft.OneDriveStandaloneUpdater",
        "us.zoom.updater",
        "us.zoom.updater.login.check",
    ]
    for svc in orphan_services:
        try:
            subprocess.run(
                ["launchctl", "disable", f"gui/{uid}/{svc}"],
                capture_output=True,
                timeout=3,
                check=False,
            )
            subprocess.run(
                ["launchctl", "remove", svc],
                capture_output=True,
                timeout=3,
                check=False,
            )
        except Exception:
            pass

    try:
        subprocess.run(
            ["qlmanage", "-r", "cache"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        messages.append("Caché de miniaturas QuickLook regenerada")
    except Exception:
        pass

    try:
        subprocess.run(
            ["dscacheutil", "-flushcache"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        messages.append("Caché DNS local limpiada")
    except Exception:
        pass

    if not messages:
        return "Optimizaciones ejecutadas."
    return "✓ " + " • ".join(messages) + "."


def reveal_in_finder(path: str) -> None:
    """Opens macOS Finder and highlights the target file or folder using `open -R`."""
    try:
        if os.path.exists(path):
            subprocess.Popen(
                ["open", "-R", path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass
