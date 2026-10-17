import os
from dataclasses import dataclass
from typing import Callable, Optional
from send2trash import send2trash

from core.models import CleanStrategy, ScanItem
from core.utils import expand_home


@dataclass
class CleanResult:
    succeeded_ids: list[str]
    bytes_freed: int
    errors_skipped: int


class SafeCleaner:
    """Executes safe deletions on macOS exclusively via Send2Trash.
    
    Enforces strict guards so root directories (`~/Library/Caches`, `~/Library/Logs`,
    `~/Library/Application Support`, `~/Library/Containers`, `~/Downloads`, `~/Library/LaunchAgents`)
    can never be trashed directly.
    """

    PROTECTED_ROOTS = {
        os.path.realpath(expand_home("~")),
        os.path.realpath(expand_home("~/.cache")),
        os.path.realpath(expand_home("~/.Trash")),
        os.path.realpath(expand_home("~/Library")),
        os.path.realpath(expand_home("~/Library/Caches")),
        os.path.realpath(expand_home("~/Library/Logs")),
        os.path.realpath(expand_home("~/Library/Application Support")),
        os.path.realpath(expand_home("~/Library/Containers")),
        os.path.realpath(expand_home("~/Library/LaunchAgents")),
        os.path.realpath(expand_home("~/Library/Saved Application State")),
        os.path.realpath(expand_home("~/Downloads")),
    }

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

        for idx, item in enumerate(items):
            if progress_callback:
                progress_callback(f"Enviando a la Papelera: {item.name}...", (idx + 1) / total)

            real_target = os.path.realpath(item.path)

            # Safety guard: Never allow trashing a root system directory directly
            if real_target in cls.PROTECTED_ROOTS and item.clean_strategy == CleanStrategy.DELETE_ITEM:
                errors_skipped += 1
                continue

            if not os.path.exists(item.path):
                succeeded_ids.append(item.id)
                continue

            if item.clean_strategy == CleanStrategy.DELETE_CONTENTS and os.path.isdir(item.path):
                freed_any, errs = cls._trash_directory_contents(item.path)
                errors_skipped += errs
                if freed_any or errs == 0:
                    succeeded_ids.append(item.id)
                    bytes_freed += item.size_bytes
            else:
                try:
                    send2trash(item.path)
                    succeeded_ids.append(item.id)
                    bytes_freed += item.size_bytes
                except (PermissionError, FileNotFoundError, OSError):
                    if os.path.isdir(item.path):
                        freed_any, errs = cls._trash_directory_contents(item.path)
                        errors_skipped += errs
                        if freed_any:
                            succeeded_ids.append(item.id)
                            bytes_freed += item.size_bytes
                    else:
                        errors_skipped += 1
                except Exception:
                    errors_skipped += 1

        return CleanResult(
            succeeded_ids=succeeded_ids,
            bytes_freed=bytes_freed,
            errors_skipped=errors_skipped,
        )

    @staticmethod
    def _trash_directory_contents(dir_path: str) -> tuple[bool, int]:
        """Sends all internal children of `dir_path` to the macOS Trash while keeping `dir_path` intact."""
        freed_any = False
        errors = 0
        try:
            with os.scandir(dir_path) as entries:
                children = [e.path for e in entries]
        except (PermissionError, FileNotFoundError, OSError):
            return False, 1

        for child_path in children:
            try:
                send2trash(child_path)
                freed_any = True
            except (PermissionError, FileNotFoundError, OSError, Exception):
                errors += 1
                continue

        return freed_any, errors
