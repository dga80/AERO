import os
import subprocess
import tempfile
import uuid
from typing import Callable, Optional

from core.app_detector import AppDetector
from core.models import CleanStrategy, ModuleType, SafetyLevel, ScanItem, ScanSummary
from core.utils import (
    abbreviate_path,
    expand_home,
    fast_dir_size,
    get_entry_size,
    get_macos_trash_size,
)


class SystemDataScanner:
    """Multithreaded-friendly macOS System Data scanner covering 5 specialized modules."""

    MIN_CACHE_LOG_BYTES = 1 * 1024 * 1024         # 1 MB minimum for Caches/Logs
    APP_REMNANTS_THRESHOLD = 200 * 1024 * 1024    # 200 MB strict requirement for Module 3
    DOWNLOADS_THRESHOLD = 500 * 1024 * 1024       # 500 MB strict requirement for Module 4

    PRIORITY_EXTENSIONS = {".dmg", ".pkg", ".zip", ".iso"}

    def __init__(self) -> None:
        self._cancel_requested = False
        self.app_detector = AppDetector()

    def cancel(self) -> None:
        self._cancel_requested = True

    def is_cancelled(self) -> bool:
        return self._cancel_requested

    def run_full_scan(
        self,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> ScanSummary:
        """Executes all 5 scan modules sequentially on a worker thread and returns a sorted ScanSummary."""
        self._cancel_requested = False
        all_items: list[ScanItem] = []

        def report(msg: str, progress: float) -> None:
            if progress_callback:
                progress_callback(msg, progress)

        report("Indexando aplicaciones instaladas en /Applications...", 0.05)
        self.app_detector.refresh_installed_apps()

        report("Escaneando Módulo 1: Cachés y Registros seguros...", 0.12)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_1_caches_and_logs(report))

        report("Escaneando Módulo 2: Basura de Desarrollo e IA (~/.cache, npm, pip, uv, Gradle)...", 0.32)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_2_dev_junk(report))

        report("Escaneando Módulo 3: Restos de Apps (> 200 MB y carpetas ocultas)...", 0.55)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_3_app_remnants(report))

        report("Escaneando Módulo 4: Descargas (> 500 MB) y Time Machine...", 0.80)
        tm_snapshots: list[str] = []
        if not self._cancel_requested:
            dl_items, tm_snapshots = self._scan_module_4_downloads_and_tm(report)
            all_items.extend(dl_items)

        report("Escaneando Módulo 5: Agentes de Inicio (LaunchAgents) y Optimización...", 0.90)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_5_optimization())

        report("Calculando tamaño físico de la Papelera de macOS (~/.Trash)...", 0.96)
        trash_bytes = get_macos_trash_size() if not self._cancel_requested else 0

        # Sort items from largest to smallest
        all_items.sort(key=lambda x: x.size_bytes, reverse=True)

        module_bytes: dict[ModuleType, int] = {
            ModuleType.CACHES_LOGS: 0,
            ModuleType.DEV_JUNK: 0,
            ModuleType.APP_REMNANTS: 0,
            ModuleType.DOWNLOADS_TM: 0,
            ModuleType.OPTIMIZATION: 0,
        }
        total_bytes = 0
        for item in all_items:
            total_bytes += item.size_bytes
            module_bytes[item.module] = module_bytes.get(item.module, 0) + item.size_bytes

        module_bytes[ModuleType.ALL] = total_bytes

        report("Análisis completado.", 1.0)
        return ScanSummary(
            items=all_items,
            tm_snapshots=tm_snapshots,
            trash_bytes=trash_bytes,
            total_bytes=total_bytes,
            module_bytes=module_bytes,
        )

    def _scan_module_1_caches_and_logs(
        self, report: Callable[[str, float], None]
    ) -> list[ScanItem]:
        """Module 1: Scans subfolders inside ~/Library/Caches and ~/Library/Logs.
        
        Excludes paths already covered in Module 2 and core Apple system caches.
        Never targets the root Caches or Logs folders themselves.
        """
        items: list[ScanItem] = []
        targets = [
            (
                expand_home("~/Library/Caches"),
                "Caché Temporal",
                "Archivos temporales de carga rápida. Se regeneran solos si la app los necesita; no borran tus datos ni sesiones.",
            ),
            (
                expand_home("~/Library/Logs"),
                "Registro (Log)",
                "Historial de texto de diagnósticos y errores antiguos. 100% seguro de eliminar.",
            ),
        ]
        excluded_names = {
            "Homebrew",
            "pip",
            "CocoaPods",
            "CloudKit",
            "FamilyCircle",
            "GeoServices",
            "PassKit",
            "audioCache.kcache",
        }

        for root_dir, tag, desc in targets:
            if self._cancel_requested or not os.path.isdir(root_dir):
                continue
            try:
                with os.scandir(root_dir) as entries:
                    entry_list = list(entries)
            except (PermissionError, FileNotFoundError, OSError):
                continue

            total_entries = max(len(entry_list), 1)
            for idx, entry in enumerate(entry_list):
                if self._cancel_requested:
                    break
                if (
                    entry.name.startswith(".")
                    or entry.name in excluded_names
                    or self.app_detector.is_apple_system_folder(entry.name)
                ):
                    continue
                try:
                    if entry.is_symlink():
                        continue
                    size = get_entry_size(entry.path, self.is_cancelled)
                    if size >= self.MIN_CACHE_LOG_BYTES:
                        if idx % 5 == 0:
                            report(f"Analizando {tag}: {entry.name}...", 0.12 + 0.18 * (idx / total_entries))
                        items.append(
                            ScanItem(
                                id=str(uuid.uuid4()),
                                name=entry.name,
                                path=entry.path,
                                abbreviated_path=abbreviate_path(entry.path),
                                size_bytes=size,
                                module=ModuleType.CACHES_LOGS,
                                clean_strategy=CleanStrategy.DELETE_ITEM,
                                safety_level=SafetyLevel.SAFE,
                                safety_badge="🟢 100% Seguro borrar",
                                description=desc,
                                category_tag=tag,
                                selected=False,
                            )
                        )
                except (PermissionError, FileNotFoundError, OSError):
                    continue

        # Scan macOS per-user temporary folders (/private/var/folders/.../<user_id>)
        if not self._cancel_requested:
            items.extend(self._scan_macos_user_temp_folders(report))

        return items

    def _scan_macos_user_temp_folders(
        self, report: Callable[[str, float], None]
    ) -> list[ScanItem]:
        """Scans the active user's Darwin temporary directories (/var/folders/.../<user_hash>)
        for orphaned temporary files (.aac, .tmp, etc.), leftover installer folders (MSau_*),
        and non-Apple user caches in T/ and C/.
        """
        items: list[ScanItem] = []
        try:
            raw_tmp = os.environ.get("TMPDIR") or tempfile.gettempdir()
            user_temp_T = os.path.realpath(raw_tmp)
            if not user_temp_T or "/var/folders/" not in user_temp_T:
                return items
            user_var_root = os.path.dirname(user_temp_T)
        except Exception:
            return items

        if not os.path.isdir(user_var_root):
            return items

        report("Analizando archivos temporales de macOS (/var/folders)...", 0.28)

        # 1. Orphaned files directly inside /private/var/folders/.../<user_hash>/ (outside 0, C, T, X)
        standard_subfolders = {"0", "C", "T", "X"}
        try:
            with os.scandir(user_var_root) as entries:
                for entry in entries:
                    if self._cancel_requested:
                        break
                    if entry.name.startswith(".") or entry.name in standard_subfolders or entry.is_symlink():
                        continue
                    try:
                        size = get_entry_size(entry.path, self.is_cancelled)
                        if size >= self.MIN_CACHE_LOG_BYTES:
                            items.append(
                                ScanItem(
                                    id=str(uuid.uuid4()),
                                    name=f"Temporal huérfano: {entry.name}",
                                    path=entry.path,
                                    abbreviated_path=entry.path,
                                    size_bytes=size,
                                    module=ModuleType.CACHES_LOGS,
                                    clean_strategy=CleanStrategy.DELETE_ITEM,
                                    safety_level=SafetyLevel.SAFE,
                                    safety_badge="🟢 100% Seguro borrar",
                                    description="Archivo temporal huérfano en /private/var/folders que nunca fue limpiado tras cerrarse la aplicación.",
                                    category_tag="Temporal macOS (/var/folders)",
                                    selected=False,
                                )
                            )
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, FileNotFoundError, OSError):
            pass

        # 2. Safe temporary items inside T/ (e.g., MSau_* Microsoft AutoUpdate temp dirs, orphaned caches)
        protected_t_names = {
            "TemporaryItems",
            "Diagnostics",
            "AudioComponentRegistrar",
            "AudioConverterService",
            "CrashHandlerService",
            "ReportCrashService",
            "SandboxHelper",
            "StatusKitAgent",
            "assessmentagent",
        }
        if os.path.isdir(user_temp_T) and not self._cancel_requested:
            try:
                with os.scandir(user_temp_T) as entries:
                    for entry in entries:
                        if self._cancel_requested:
                            break
                        if (
                            entry.name.startswith(".")
                            or entry.name in protected_t_names
                            or entry.is_symlink()
                            or self.app_detector.is_apple_system_folder(entry.name)
                        ):
                            continue
                        try:
                            size = get_entry_size(entry.path, self.is_cancelled)
                            if size >= self.MIN_CACHE_LOG_BYTES:
                                is_msau = entry.name.startswith("MSau_")
                                desc = (
                                    "Carpeta temporal antigua del actualizador de Microsoft (AutoUpdate) en $TMPDIR. 100% seguro borrar."
                                    if is_msau
                                    else "Carpeta o archivo temporal de aplicación en $TMPDIR (/var/folders/.../T). 100% seguro borrar."
                                )
                                items.append(
                                    ScanItem(
                                        id=str(uuid.uuid4()),
                                        name=f"{entry.name} (Temp T)" if not is_msau else f"Microsoft AutoUpdate Temp ({entry.name})",
                                        path=entry.path,
                                        abbreviated_path=entry.path,
                                        size_bytes=size,
                                        module=ModuleType.CACHES_LOGS,
                                        clean_strategy=CleanStrategy.DELETE_ITEM,
                                        safety_level=SafetyLevel.SAFE,
                                        safety_badge="🟢 100% Seguro borrar",
                                        description=desc,
                                        category_tag="Carpeta Temporal ($TMPDIR)",
                                        selected=False,
                                    )
                                )
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, FileNotFoundError, OSError):
                pass

        # 3. Non-Apple application caches inside C/ (/private/var/folders/.../C)
        user_temp_C = os.path.join(user_var_root, "C")
        if os.path.isdir(user_temp_C) and not self._cancel_requested:
            try:
                with os.scandir(user_temp_C) as entries:
                    for entry in entries:
                        if self._cancel_requested:
                            break
                        if (
                            entry.name.startswith(".")
                            or entry.is_symlink()
                            or self.app_detector.is_apple_system_folder(entry.name)
                        ):
                            continue
                        try:
                            size = get_entry_size(entry.path, self.is_cancelled)
                            if size >= self.MIN_CACHE_LOG_BYTES:
                                items.append(
                                    ScanItem(
                                        id=str(uuid.uuid4()),
                                        name=f"{entry.name} (Caché Darwin)",
                                        path=entry.path,
                                        abbreviated_path=entry.path,
                                        size_bytes=size,
                                        module=ModuleType.CACHES_LOGS,
                                        clean_strategy=CleanStrategy.DELETE_ITEM,
                                        safety_level=SafetyLevel.SAFE,
                                        safety_badge="🟢 100% Seguro borrar",
                                        description="Caché temporal de aplicación en /private/var/folders/.../C. Se regenera sola si la aplicación la necesita.",
                                        category_tag="Caché Darwin (/var/folders)",
                                        selected=False,
                                    )
                                )
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, FileNotFoundError, OSError):
                pass

        return items

    def _scan_module_2_dev_junk(
        self, report: Callable[[str, float], None]
    ) -> list[ScanItem]:
        """Module 2: Verifies existence and calculates size of key developer & AI caches."""
        dev_targets = [
            (
                "Xcode DerivedData",
                "~/Library/Developer/Xcode/DerivedData",
                "Xcode",
                "Archivos intermedios de compilación de Xcode. 100% seguro borrar (Xcode los recompila si abres el proyecto).",
            ),
            (
                "CoreSimulator Caches",
                "~/Library/Developer/CoreSimulator/Caches",
                "iOS Simulator",
                "Cachés temporales de simuladores de iOS/macOS. 100% seguro borrar.",
            ),
            (
                "HuggingFace Cache (Modelos IA)",
                "~/.cache/huggingface",
                "IA / HuggingFace",
                "Pesos y modelos de Inteligencia Artificial descargados en caché (~/.cache/huggingface). 100% seguro borrar si no los usas activamente.",
            ),
            (
                "uv Cache (Paquetes Python)",
                "~/.cache/uv",
                "Python / uv",
                "Caché oculta de ruedas y paquetes descargados por el gestor 'uv'. 100% seguro borrar; no afecta a tus entornos virtuales.",
            ),
            (
                "NPM Cache (_cacache)",
                "~/.npm/_cacache",
                "Node.js / npm",
                "Copias descargadas de paquetes antiguos de Node.js (npm). 100% seguro borrar; no afecta a tus proyectos.",
            ),
            (
                "NPX Cache (_npx)",
                "~/.npm/_npx",
                "Node.js / npx",
                "Entornos y paquetes temporales descargados al ejecutar herramientas con 'npx' (~/.npm/_npx). 100% seguro borrar.",
            ),
            (
                "Yarn Cache",
                "~/Library/Caches/Yarn",
                "Node.js / Yarn",
                "Caché de paquetes descargados por el gestor Yarn. 100% seguro borrar.",
            ),
            (
                "pnpm Store Cache",
                "~/Library/pnpm/store",
                "Node.js / pnpm",
                "Almacén en caché de paquetes descargados por pnpm. 100% seguro borrar.",
            ),
            (
                "Bun Install Cache",
                "~/.bun/install/cache",
                "Node.js / Bun",
                "Caché de paquetes descargados por el runtime Bun. 100% seguro borrar.",
            ),
            (
                "PyInstaller Build Cache",
                "~/Library/Application Support/pyinstaller",
                "Python / PyInstaller",
                "Caché de binarios y bootloaders precompilados de PyInstaller. 100% seguro borrar.",
            ),
            (
                "Python Bytecode Cache (com.apple.python)",
                "~/Library/Caches/com.apple.python",
                "Python / macOS",
                "Archivos .pyc precompilados generados por el intérprete Python de macOS. 100% seguro borrar (se regeneran automáticamente).",
            ),
            (
                "Gradle Cache (Java / Android)",
                "~/.gradle/caches",
                "Gradle",
                "Caché oculta de compilación y dependencias descargadas por Gradle. 100% seguro borrar.",
            ),
            (
                "Gradle Wrapper Distributions",
                "~/.gradle/wrapper/dists",
                "Gradle",
                "Versiones antiguas del motor Gradle descargadas automáticamente. 100% seguro borrar.",
            ),
            (
                "pip Cache",
                "~/Library/Caches/pip",
                "Python / pip",
                "Paquetes .whl antiguos descargados al instalar librerías de Python. 100% seguro borrar.",
            ),
            (
                "Flutter / Dart Pub Cache",
                "~/.pub-cache",
                "Flutter / Dart",
                "Caché oculta de paquetes descargados por Flutter/Dart (pub.dev). 100% seguro borrar.",
            ),
            (
                "Homebrew Cache",
                "~/Library/Caches/Homebrew",
                "Homebrew",
                "Instaladores antiguos ya descargados por Homebrew. 100% seguro borrar.",
            ),
            (
                "Maven Repository Cache",
                "~/.m2/repository",
                "Java / Maven",
                "Repositorio local en caché de librerías Java (Maven). 100% seguro borrar.",
            ),
            (
                "Cargo Cache (Rust)",
                "~/.cargo/registry",
                "Rust / Cargo",
                "Caché de crates descargados por Rust Cargo. 100% seguro borrar.",
            ),
            (
                "CocoaPods Cache",
                "~/Library/Caches/CocoaPods",
                "iOS / CocoaPods",
                "Caché de pods descargados para proyectos de iOS/macOS. 100% seguro borrar.",
            ),
        ]
        items: list[ScanItem] = []
        covered_paths: set[str] = set()

        for idx, (label, raw_path, tag, desc) in enumerate(dev_targets):
            if self._cancel_requested:
                break
            full_path = expand_home(raw_path)
            covered_paths.add(os.path.realpath(full_path))
            if not os.path.exists(full_path):
                continue
            report(f"Calculando Desarrollo e IA: {label}...", 0.32 + 0.16 * ((idx + 1) / len(dev_targets)))
            size = fast_dir_size(full_path, self.is_cancelled)
            if size >= self.MIN_CACHE_LOG_BYTES:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name=label,
                        path=full_path,
                        abbreviated_path=abbreviate_path(full_path),
                        size_bytes=size,
                        module=ModuleType.DEV_JUNK,
                        clean_strategy=CleanStrategy.DELETE_CONTENTS,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 100% Seguro borrar",
                        description=desc,
                        category_tag=tag,
                        selected=False,
                    )
                )

        # Dynamically scan all subdirectories inside ~/.cache so no dev/AI cache (e.g., prisma, antigravity, playwright, cypress) is missed
        dot_cache_root = expand_home("~/.cache")
        if os.path.isdir(dot_cache_root) and not self._cancel_requested:
            try:
                with os.scandir(dot_cache_root) as entries:
                    for entry in entries:
                        if self._cancel_requested:
                            break
                        if entry.name.startswith(".") or entry.is_symlink():
                            continue
                        real_sub = os.path.realpath(entry.path)
                        if real_sub in covered_paths:
                            continue
                        try:
                            size = get_entry_size(entry.path, self.is_cancelled)
                            if size >= self.MIN_CACHE_LOG_BYTES:
                                items.append(
                                    ScanItem(
                                        id=str(uuid.uuid4()),
                                        name=f"~/.cache/{entry.name}",
                                        path=entry.path,
                                        abbreviated_path=abbreviate_path(entry.path),
                                        size_bytes=size,
                                        module=ModuleType.DEV_JUNK,
                                        clean_strategy=CleanStrategy.DELETE_ITEM,
                                        safety_level=SafetyLevel.SAFE,
                                        safety_badge="🟢 100% Seguro borrar",
                                        description=(
                                            f"Caché de herramientas de desarrollo o IA en ~/.cache/{entry.name}. "
                                            "100% seguro borrar; se vuelve a descargar si la herramienta lo necesita."
                                        ),
                                        category_tag="Caché (~/.cache)",
                                        selected=False,
                                    )
                                )
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, FileNotFoundError, OSError):
                pass

        return items

    def _scan_module_3_app_remnants(
        self, report: Callable[[str, float], None]
    ) -> list[ScanItem]:
        """Module 3: Scans ~/Library/Application Support, ~/Library/Containers (> 200 MB),
        plus known heavy hidden app-remnant folders in `~` (`.vscode`, `.android`, `.rvm`, etc.).
        """
        items: list[ScanItem] = []
        targets = [
            (expand_home("~/Library/Application Support"), "Application Support"),
            (expand_home("~/Library/Containers"), "Containers"),
        ]

        for root_dir, tag in targets:
            if self._cancel_requested or not os.path.isdir(root_dir):
                continue
            try:
                with os.scandir(root_dir) as entries:
                    subdirs = [
                        e
                        for e in entries
                        if not e.name.startswith(".")
                        and not e.is_symlink()
                        and e.is_dir(follow_symlinks=False)
                        and not self.app_detector.is_apple_system_folder(e.name)
                    ]
            except (PermissionError, FileNotFoundError, OSError):
                continue

            total_dirs = max(len(subdirs), 1)
            for idx, entry in enumerate(subdirs):
                if self._cancel_requested:
                    break
                if idx % 4 == 0:
                    report(
                        f"Inspeccionando {tag}: {entry.name}...",
                        0.55 + 0.18 * (idx / total_dirs),
                    )
                try:
                    size = fast_dir_size(entry.path, self.is_cancelled)
                    if size > self.APP_REMNANTS_THRESHOLD:
                        safety_level, badge, desc, warning = self.app_detector.classify_app_remnant(
                            entry.name, tag
                        )
                        items.append(
                            ScanItem(
                                id=str(uuid.uuid4()),
                                name=entry.name,
                                path=entry.path,
                                abbreviated_path=abbreviate_path(entry.path),
                                size_bytes=size,
                                module=ModuleType.APP_REMNANTS,
                                clean_strategy=CleanStrategy.DELETE_ITEM,
                                safety_level=safety_level,
                                safety_badge=badge,
                                description=desc,
                                warning_label=warning,
                                category_tag=tag,
                                selected=False,
                            )
                        )
                except (PermissionError, FileNotFoundError, OSError):
                    continue

        # Also inspect known hidden app-data folders in ~ (> 200 MB) that uninstalled apps leave behind
        hidden_app_folders = [
            (".vscode", "~/.vscode", "Carpeta Oculta (~)"),
            (".android", "~/.android", "Carpeta Oculta (~)"),
            (".rvm", "~/.rvm", "Carpeta Oculta (~)"),
            (".ollama", "~/.ollama", "Carpeta Oculta (~)"),
            (".lmstudio", "~/.lmstudio", "Carpeta Oculta (~)"),
            (".cursor", "~/.cursor", "Carpeta Oculta (~)"),
            (".local/share/powershell", "~/.local/share/powershell", "Datos Locales (~/.local)"),
        ]
        for folder_key, raw_path, tag in hidden_app_folders:
            if self._cancel_requested:
                break
            full_path = expand_home(raw_path)
            if not os.path.isdir(full_path) or os.path.islink(full_path):
                continue
            size = fast_dir_size(full_path, self.is_cancelled)
            if size > self.APP_REMNANTS_THRESHOLD:
                safety_level, badge, desc, warning = self.app_detector.classify_app_remnant(
                    folder_key, tag
                )
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name=f"{folder_key} ({abbreviate_path(full_path)})",
                        path=full_path,
                        abbreviated_path=abbreviate_path(full_path),
                        size_bytes=size,
                        module=ModuleType.APP_REMNANTS,
                        clean_strategy=CleanStrategy.DELETE_ITEM,
                        safety_level=safety_level,
                        safety_badge=badge,
                        description=desc,
                        warning_label=warning,
                        category_tag=tag,
                        selected=False,
                    )
                )

        return items

    def _scan_module_4_downloads_and_tm(
        self, report: Callable[[str, float], None]
    ) -> tuple[list[ScanItem], list[str]]:
        """Module 4: Scans ~/Downloads for files > 500 MB and inspects local Time Machine snapshots."""
        items: list[ScanItem] = []
        downloads_dir = expand_home("~/Downloads")

        if os.path.isdir(downloads_dir) and not self._cancel_requested:
            try:
                with os.scandir(downloads_dir) as entries:
                    for entry in entries:
                        if self._cancel_requested:
                            break
                        if entry.name.startswith(".") or entry.is_symlink():
                            continue
                        try:
                            size = get_entry_size(entry.path, self.is_cancelled)
                            if size > self.DOWNLOADS_THRESHOLD:
                                _, ext = os.path.splitext(entry.name.lower())
                                is_priority = ext in self.PRIORITY_EXTENSIONS
                                if is_priority:
                                    tag = f"Instalador ({ext})"
                                    safety = SafetyLevel.SAFE
                                    badge = "🟢 Instalador antiguo (Seguro)"
                                    desc = (
                                        f"Archivo instalador o imagen comprimida ({ext}) en tu carpeta Descargas. "
                                        "Si ya instalaste el programa, puedes borrarlo sin problema."
                                    )
                                else:
                                    tag = "Archivo Pesado"
                                    safety = SafetyLevel.REVIEW
                                    badge = "🟡 Archivo personal (Revisar)"
                                    desc = "Archivo grande en tu carpeta Descargas. Verifica si aún lo necesitas antes de enviarlo a la Papelera."

                                items.append(
                                    ScanItem(
                                        id=str(uuid.uuid4()),
                                        name=entry.name,
                                        path=entry.path,
                                        abbreviated_path=abbreviate_path(entry.path),
                                        size_bytes=size,
                                        module=ModuleType.DOWNLOADS_TM,
                                        clean_strategy=CleanStrategy.DELETE_ITEM,
                                        safety_level=safety,
                                        safety_badge=badge,
                                        description=desc,
                                        category_tag=tag,
                                        selected=False,
                                        is_priority_archive=is_priority,
                                    )
                                )
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, FileNotFoundError, OSError):
                pass

        report("Verificando instantáneas locales de Time Machine (tmutil)...", 0.86)
        tm_snapshots = self._detect_time_machine_snapshots()
        return items, tm_snapshots

    def _scan_module_5_optimization(self) -> list[ScanItem]:
        """Module 5: Scans ~/Library/LaunchAgents for orphaned/broken startup agents
        and ~/Library/Saved Application State for old window states.
        """
        items: list[ScanItem] = []

        # 1. Orphaned LaunchAgents in ~/Library/LaunchAgents
        la_dir = expand_home("~/Library/LaunchAgents")
        if os.path.isdir(la_dir) and not self._cancel_requested:
            try:
                with os.scandir(la_dir) as entries:
                    for entry in entries:
                        if not entry.name.endswith(".plist") or entry.is_symlink():
                            continue
                        res = self.app_detector.inspect_launch_agent(entry.path)
                        if res is not None:
                            safety_level, badge, desc, warning = res
                            size = get_entry_size(entry.path)
                            items.append(
                                ScanItem(
                                    id=str(uuid.uuid4()),
                                    name=entry.name,
                                    path=entry.path,
                                    abbreviated_path=abbreviate_path(entry.path),
                                    size_bytes=max(size, 4096),
                                    module=ModuleType.OPTIMIZATION,
                                    clean_strategy=CleanStrategy.DELETE_ITEM,
                                    safety_level=safety_level,
                                    safety_badge=badge,
                                    description=desc,
                                    warning_label=warning,
                                    category_tag="Agente de Inicio (RAM)",
                                    selected=False,
                                )
                            )
            except (PermissionError, FileNotFoundError, OSError):
                pass

        # 2. If Microsoft Edge is uninstalled but ~/Library/Microsoft/EdgeUpdater exists, flag that updater folder too
        edge_updater_dir = expand_home("~/Library/Microsoft/EdgeUpdater")
        if (
            os.path.isdir(edge_updater_dir)
            and "microsoftedge" not in self.app_detector.installed_app_names
        ):
            sz = fast_dir_size(edge_updater_dir, self.is_cancelled)
            if sz > 0:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name="Microsoft EdgeUpdater (Servicio Fantasma)",
                        path=edge_updater_dir,
                        abbreviated_path=abbreviate_path(edge_updater_dir),
                        size_bytes=sz,
                        module=ModuleType.OPTIMIZATION,
                        clean_strategy=CleanStrategy.DELETE_ITEM,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 App desinstalada (Seguro borrar)",
                        description="Ejecutables en segundo plano de Microsoft EdgeUpdater que quedaron tras desinstalar Edge.",
                        warning_label="🟢 100% SEGURO BORRAR: Elimina el actualizador oculto de Microsoft Edge.",
                        category_tag="Proceso en Segundo Plano",
                        selected=False,
                    )
                )

        # 3. Saved Application State (~/Library/Saved Application State)
        saved_state_dir = expand_home("~/Library/Saved Application State")
        if os.path.isdir(saved_state_dir) and not self._cancel_requested:
            sz = fast_dir_size(saved_state_dir, self.is_cancelled)
            if sz >= self.MIN_CACHE_LOG_BYTES:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name="Estados de Ventanas Antiguas (Saved Application State)",
                        path=saved_state_dir,
                        abbreviated_path=abbreviate_path(saved_state_dir),
                        size_bytes=sz,
                        module=ModuleType.OPTIMIZATION,
                        clean_strategy=CleanStrategy.DELETE_CONTENTS,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 100% Seguro borrar",
                        description="Posición recordada de ventanas de programas antiguos o cerrados. 100% seguro de limpiar.",
                        category_tag="Optimización macOS",
                        selected=False,
                    )
                )

        return items

    @staticmethod
    def _detect_time_machine_snapshots() -> list[str]:
        """Runs `tmutil listlocalsnapshots /` via subprocess and parses snapshot names."""
        snapshots: list[str] = []
        try:
            proc = subprocess.run(
                ["tmutil", "listlocalsnapshots", "/"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    clean = line.strip()
                    if not clean or clean.startswith("Snapshots for"):
                        continue
                    if "com.apple.TimeMachine" in clean or clean.startswith("com.apple."):
                        snapshots.append(clean)
        except Exception:
            pass
        return snapshots
