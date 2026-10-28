from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ModuleType(Enum):
    ALL = "Todos los Módulos"
    CACHES_LOGS = "Cachés y Temporales"
    DEV_JUNK = "Desarrollo e IA"
    APP_REMNANTS = "Restos de Programas"
    DOWNLOADS_TM = "Descargas y Restauración"
    OPTIMIZATION = "Inicio y Optimización"
    RAM_MONITOR = "Monitor y Turbo RAM"


class CleanStrategy(Enum):
    """Defines how an item is sent to the Windows Recycle Bin.
    
    - DELETE_ITEM: Sends the target file or subfolder itself to the Recycle Bin.
      Used when the ScanItem represents a specific subfolder inside AppData/Temp
      or a specific file inside ~/Downloads, so the root folder is untouched.
    - DELETE_CONTENTS: Sends only the internal children of the directory to the Recycle Bin,
      preserving the parent folder itself (ideal for root Temp or Dev cache folders).
    """
    DELETE_ITEM = "delete_item"
    DELETE_CONTENTS = "delete_contents"


class SafetyLevel(Enum):
    """Safety classification to guide non-technical users on what can be safely deleted."""
    SAFE = "safe"              # 100% safe temporary cache, logs, or confirmed uninstalled app remnant
    INSTALLED_APP = "active"   # Belongs to a currently installed app — warns user not to delete blindly
    REVIEW = "review"          # Unknown/manual folder or user download — requires quick look


@dataclass
class ScanItem:
    id: str
    name: str
    path: str
    abbreviated_path: str
    size_bytes: int
    module: ModuleType
    clean_strategy: CleanStrategy
    safety_level: SafetyLevel = SafetyLevel.SAFE
    safety_badge: str = "🟢 100% Seguro borrar"
    description: str = ""
    warning_label: Optional[str] = None
    category_tag: str = ""
    selected: bool = False
    is_priority_archive: bool = False


@dataclass
class ScanSummary:
    items: list[ScanItem]
    tm_snapshots: list[str]
    trash_bytes: int
    total_bytes: int
    module_bytes: dict[ModuleType, int]
