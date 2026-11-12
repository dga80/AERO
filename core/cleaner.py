import functools
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional
from send2trash import send2trash

from core.models import CleanStrategy, ScanItem
from core.utils import CREATE_NO_WINDOW, expand_home, fast_dir_size, is_user_admin


@dataclass
class CleanResult:
    succeeded_ids: list[str]
    bytes_freed: int
    errors_skipped: int


@functools.lru_cache(maxsize=1)
def _get_protected_roots() -> set[str]:
    return {
        os.path.normcase(os.path.realpath(expand_home("~"))),
        os.path.normcase(os.path.realpath(expand_home("~/.cache"))),
        os.path.normcase(os.path.realpath(expand_home("~/Downloads"))),
        os.path.normcase(os.path.realpath(expand_home("~/Desktop"))),
        os.path.normcase(os.path.realpath(expand_home("~/Documents"))),
        os.path.normcase(os.path.realpath(expand_home(r"%LOCALAPPDATA%"))),
        os.path.normcase(os.path.realpath(expand_home(r"%LOCALAPPDATA%\Temp"))),
        os.path.normcase(os.path.realpath(expand_home(r"%APPDATA%"))),
        os.path.normcase(os.path.realpath(expand_home(r"%PROGRAMDATA%"))),
        os.path.normcase(os.path.realpath(expand_home(r"%WINDIR%"))),
        os.path.normcase(os.path.realpath(expand_home(r"%WINDIR%\Temp"))),
    }


def _is_software_distribution_download(path: str) -> bool:
    """Checks if the given path points to %WINDIR%\\SoftwareDistribution\\Download."""
    try:
        norm = os.path.normcase(os.path.realpath(os.path.normpath(path)))
        sw = os.path.normcase(os.path.realpath(expand_home(r"%WINDIR%\SoftwareDistribution\Download")))
        return norm == sw
    except Exception:
        return False


def _is_system_path(path: str) -> bool:
    """Checks if path is located inside C:\\Windows."""
    try:
        norm = os.path.normcase(os.path.realpath(os.path.normpath(path)))
        windir = os.path.normcase(os.path.realpath(expand_home(r"%WINDIR%")))
        return norm.startswith(windir)
    except Exception:
        return False


class SafeCleaner:
    """Executes safe deletions on Windows.
    
    Uses Send2Trash (Papelera de reciclaje) for user-level caches and downloads.
    For system directories where Windows forbids moving files to Recycle Bin (such as
    C:\\Windows\\Temp or Windows Update Download cache), it employs dedicated permanent
    cleaning routines with Windows service management (wuauserv, dosvc, bits).
    
    Enforces strict guards so root user/system directories (%USERPROFILE%, %LOCALAPPDATA%,
    %APPDATA%, %TEMP%, ~/Downloads, C:\\Windows, C:\\ProgramData)
    can never be deleted directly as a single item.
    """

    @classmethod
    def clean_items(
        cls,
        items: list[ScanItem],
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> CleanResult:
        succeeded_ids: list[str] = []
        bytes_freed = 0
        errors_skipped = 0
        total = max(len(items), 1)
        protected_roots = _get_protected_roots()

        for idx, item in enumerate(items):
            current_progress = (idx + 1) / total
            if progress_callback:
                progress_callback(
                    f"Limpiando: {item.name}...",
                    current_progress,
                )

            norm_target = os.path.normcase(os.path.realpath(os.path.normpath(item.path)))

            # Safety guard: Never allow deleting a root system directory directly
            if norm_target in protected_roots and item.clean_strategy == CleanStrategy.DELETE_ITEM:
                errors_skipped += 1
                continue

            if not os.path.exists(item.path):
                succeeded_ids.append(item.id)
                continue

            target_path = os.path.normpath(item.path)

            # Special case 1: Windows Update Download Cache (SoftwareDistribution\Download)
            if _is_software_distribution_download(target_path):
                freed_any, errs, actual_freed = cls._clean_software_distribution(
                    target_path,
                    progress_callback=progress_callback,
                    progress_val=current_progress,
                )
                errors_skipped += errs
                if freed_any or errs == 0:
                    succeeded_ids.append(item.id)
                    bytes_freed += actual_freed if actual_freed > 0 else item.size_bytes
                continue

            # Standard directory contents cleaning
            if item.clean_strategy == CleanStrategy.DELETE_CONTENTS and os.path.isdir(target_path):
                freed_any, errs = cls._trash_directory_contents(target_path)
                errors_skipped += errs
                if freed_any or errs == 0:
                    succeeded_ids.append(item.id)
                    bytes_freed += item.size_bytes
            else:
                try:
                    send2trash(target_path)
                    succeeded_ids.append(item.id)
                    bytes_freed += item.size_bytes
                except (PermissionError, FileNotFoundError, OSError):
                    # On Windows, if a file inside a folder is locked, fall back to cleaning unlocked children
                    if os.path.isdir(target_path):
                        freed_any, errs = cls._trash_directory_contents(target_path)
                        errors_skipped += errs
                        if freed_any:
                            succeeded_ids.append(item.id)
                            bytes_freed += item.size_bytes
                    elif is_user_admin() and _is_system_path(target_path):
                        if cls._permanent_delete_entry(target_path):
                            succeeded_ids.append(item.id)
                            bytes_freed += item.size_bytes
                        else:
                            errors_skipped += 1
                    else:
                        errors_skipped += 1
                except Exception:
                    errors_skipped += 1

        return CleanResult(
            succeeded_ids=succeeded_ids,
            bytes_freed=bytes_freed,
            errors_skipped=errors_skipped,
        )

    @classmethod
    def _clean_software_distribution(
        cls,
        dir_path: str,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        progress_val: float = 0.5,
    ) -> tuple[bool, int, int]:
        """Cleans Windows Update downloads by stopping wuauserv, dosvc, and bits to
        release active locks, removing all children, and restarting the services.
        Returns: (freed_any, errors, actual_freed_bytes)
        """
        initial_size = fast_dir_size(dir_path)
        if initial_size <= 0:
            return True, 0, 0

        # If not admin, services cannot be stopped and system folder cannot be modified
        if not is_user_admin():
            if progress_callback:
                progress_callback(
                    "Error: Se requieren permisos de Administrador para limpiar Windows Update.",
                    progress_val,
                )
            return False, 1, 0

        services_to_stop = ["wuauserv", "dosvc", "bits"]

        if progress_callback:
            progress_callback("Deteniendo servicios de Windows Update (wuauserv, dosvc, bits)...", progress_val)

        for svc in services_to_stop:
            try:
                subprocess.run(
                    ["net", "stop", svc, "/y"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    creationflags=CREATE_NO_WINDOW,
                    check=False,
                )
            except Exception:
                pass

        # Brief pause to allow svchost.exe to close active handles
        import time
        time.sleep(1.0)

        freed_any = False
        errors = 0

        try:
            if progress_callback:
                progress_callback("Eliminando paquetes de actualización descargados...", progress_val)

            try:
                with os.scandir(dir_path) as entries:
                    children = [os.path.normpath(e.path) for e in entries]
            except Exception:
                children = []
                errors += 1

            for child in children:
                if cls._permanent_delete_entry(child):
                    freed_any = True
                else:
                    errors += 1

            # Fallback wildcard cleanup if any subfolder remains
            if os.path.exists(dir_path):
                try:
                    if os.listdir(dir_path):
                        subprocess.run(
                            [
                                "powershell",
                                "-NoProfile",
                                "-Command",
                                f"Remove-Item -Path '{dir_path}\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=25,
                            creationflags=CREATE_NO_WINDOW,
                            check=False,
                        )
                except Exception:
                    pass
        finally:
            if progress_callback:
                progress_callback("Reiniciando servicios de Windows Update...", progress_val)

            for svc in reversed(services_to_stop):
                try:
                    subprocess.run(
                        ["net", "start", svc],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                        creationflags=CREATE_NO_WINDOW,
                        check=False,
                    )
                except Exception:
                    pass

        final_size = fast_dir_size(dir_path)
        actual_freed = max(0, initial_size - final_size)
        if actual_freed > 0 or (os.path.exists(dir_path) and len(os.listdir(dir_path)) == 0):
            freed_any = True

        return freed_any, errors, actual_freed

    @classmethod
    def _trash_directory_contents(cls, dir_path: str) -> tuple[bool, int]:
        """Sends internal children of dir_path to Recycle Bin while keeping dir_path intact.
        If send2trash fails because the path is a system directory (e.g. C:\\Windows\\Temp),
        falls back to safe permanent deletion of the unlocked temporary files.
        """
        freed_any = False
        errors = 0
        try:
            with os.scandir(dir_path) as entries:
                children = [os.path.normpath(e.path) for e in entries]
        except (PermissionError, FileNotFoundError, OSError):
            return False, 1

        is_system = _is_system_path(dir_path)

        for child_path in children:
            trashed = False
            try:
                send2trash(child_path)
                trashed = True
                freed_any = True
            except Exception:
                trashed = False

            if not trashed:
                # If send2trash failed on a system directory (Windows forbids trashing C:\Windows files),
                # fall back to permanent deletion if we have permissions.
                if is_system or is_user_admin():
                    if cls._permanent_delete_entry(child_path):
                        freed_any = True
                    else:
                        errors += 1
                else:
                    errors += 1

        return freed_any, errors

    @staticmethod
    def _permanent_delete_entry(path: str) -> bool:
        """Permanently removes a file or directory, clearing read-only attributes and falling back to OS utilities."""
        if not os.path.exists(path) and not os.path.islink(path):
            return True

        # Helper to strip read-only / system attributes
        def _clear_attributes(p: str) -> None:
            try:
                import ctypes
                # FILE_ATTRIBUTE_NORMAL = 0x80
                ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
            except Exception:
                pass
            try:
                os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

        _clear_attributes(path)

        # 1. Native Python removal
        if os.path.islink(path) or os.path.isfile(path):
            try:
                os.unlink(path)
                return True
            except Exception:
                pass
        elif os.path.isdir(path):
            def _remove_readonly(func, p, exc_info):
                _clear_attributes(p)
                try:
                    func(p)
                except Exception:
                    pass

            try:
                shutil.rmtree(path, onerror=_remove_readonly)
                if not os.path.exists(path):
                    return True
            except Exception:
                pass

        # 2. Windows cmd rd /s /q or del /f /q fallback
        try:
            if os.path.isdir(path):
                subprocess.run(
                    ["cmd.exe", "/c", "rd", "/s", "/q", path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    creationflags=CREATE_NO_WINDOW,
                    check=False,
                )
            else:
                subprocess.run(
                    ["cmd.exe", "/c", "del", "/f", "/q", "/a", path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    creationflags=CREATE_NO_WINDOW,
                    check=False,
                )
            if not os.path.exists(path):
                return True
        except Exception:
            pass

        # 3. PowerShell Remove-Item fallback
        try:
            subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"Remove-Item -LiteralPath '{path}' -Recurse -Force -ErrorAction SilentlyContinue",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                creationflags=CREATE_NO_WINDOW,
                check=False,
            )
            if not os.path.exists(path):
                return True
        except Exception:
            pass

        return not os.path.exists(path)
