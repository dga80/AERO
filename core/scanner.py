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
    APP_REMNANTS_THRESHOLD = 200 * 1024 * 1024    # 200 MB requirement for active installed apps
    ORPHAN_REMNANTS_THRESHOLD = 10 * 1024 * 1024  # 10 MB requirement for uninstalled (orphaned) apps
    PROJECT_ENV_THRESHOLD = 40 * 1024 * 1024      # 40 MB requirement for ~/Proyectos venv/node_modules
    DOWNLOADS_THRESHOLD = 500 * 1024 * 1024       # 500 MB strict requirement for Module 4

    PRIORITY_EXTENSIONS = {".dmg", ".pkg", ".zip", ".iso"}

    SAFE_APPLE_USER_CACHES: dict[str, str] = {
        "GeoServices": "Caché local de mapas y geolocalización de macOS (GeoServices). Se regenera automáticamente.",
        "com.apple.helpd": "Caché temporal del visor de Ayuda de macOS (helpd). 100% seguro limpiar.",
        "com.apple.intelligenceflow.intelligenceflowd": "Caché temporal de flujos de IA del sistema (intelligenceflowd). 100% seguro limpiar.",
        "com.apple.VisualIntelligenceCore": "Caché temporal de análisis visual del sistema. 100% seguro limpiar.",
        "com.apple.e5rt.e5bundlecache": "Caché de modelos precompilados del Neural Engine (e5bundlecache). Se regenera sola bajo demanda.",
        "com.apple.parsecd": "Caché temporal de sugerencias de Spotlight y Siri (parsecd). 100% seguro limpiar.",
        "com.apple.AppleMediaServices": "Caché temporal de Apple Media Services. 100% seguro limpiar.",
        "com.apple.CloudTelemetry": "Caché local de telemetría en la nube de macOS. 100% seguro limpiar.",
        "com.apple.amsengagementd": "Caché de avisos y promociones de Apple Media Services. 100% seguro limpiar.",
        "com.apple.preferencepanes.usercache": "Caché de paneles de Ajustes del Sistema. Se regenera al abrir Ajustes.",
        "com.apple.tipsd": "Caché de vídeos y tarjetas de la app Consejos (Tips) de macOS. 100% seguro limpiar.",
        "com.apple.appstoreagent": "Caché temporal del agente de Mac App Store. 100% seguro limpiar.",
    }

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
                is_safe_apple_cache = entry.name in self.SAFE_APPLE_USER_CACHES
                if (
                    entry.name.startswith(".")
                    or entry.name in excluded_names
                    or (not is_safe_apple_cache and self.app_detector.is_apple_system_folder(entry.name))
                ):
                    continue
                try:
                    if entry.is_symlink():
                        continue
                    size = get_entry_size(entry.path, self.is_cancelled)
                    if size >= self.MIN_CACHE_LOG_BYTES:
                        if idx % 5 == 0:
                            report(f"Analizando {tag}: {entry.name}...", 0.12 + 0.14 * (idx / total_entries))
                        item_desc = self.SAFE_APPLE_USER_CACHES.get(entry.name, desc)
                        item_strategy = (
                            CleanStrategy.DELETE_CONTENTS if is_safe_apple_cache else CleanStrategy.DELETE_ITEM
                        )
                        items.append(
                            ScanItem(
                                id=str(uuid.uuid4()),
                                name=entry.name,
                                path=entry.path,
                                abbreviated_path=abbreviate_path(entry.path),
                                size_bytes=size,
                                module=ModuleType.CACHES_LOGS,
                                clean_strategy=item_strategy,
                                safety_level=SafetyLevel.SAFE,
                                safety_badge="🟢 100% Seguro borrar",
                                description=item_desc,
                                category_tag="Caché Sistema macOS" if is_safe_apple_cache else tag,
                                selected=False,
                            )
                        )
                except (PermissionError, FileNotFoundError, OSError):
                    continue

        # Scan safe internal app caches & 4K aerial wallpaper videos in ~/Library/Application Support
        special_app_support_caches = [
            (
                "Fondos de Pantalla en Vídeo 4K (Aerials .mov)",
                "~/Library/Application Support/com.apple.wallpaper/aerials/videos",
                "Fondos 4K (Disco + GPU)",
                (
                    "Vídeos 4K (.mov) descargados para salvapantallas/fondos dinámicos de macOS. "
                    "Limpiarlos libera más de 1 GB y evita que WallpaperAerialsExtension decodifique vídeo 4K al iniciar sesión."
                ),
            ),
            (
                "Adobe Dunamis Telemetry Cache (com.adobe.dunamis)",
                "~/Library/Application Support/com.adobe.dunamis",
                "Telemetría Adobe",
                "Registros analíticos y telemetría acumulada en segundo plano por Adobe (Dunamis). 100% seguro limpiar.",
            ),
            (
                "CoreML Compiled Model Cache (coreMLCache)",
                "~/Library/Application Support/coreMLCache",
                "Caché CoreML",
                "Caché temporal de modelos CoreML compilados en Application Support. Se regenera bajo demanda.",
            ),
            (
                "Antigravity Electron Code Cache",
                "~/Library/Application Support/Antigravity/Code Cache",
                "Caché App (Electron)",
                "Caché de bytecode JS/WASM de Antigravity. 100% seguro limpiar sin afectar tus ajustes ni sesión.",
            ),
            (
                "Antigravity Electron HTTP Cache",
                "~/Library/Application Support/Antigravity/Cache",
                "Caché App (Electron)",
                "Caché temporal de recursos de red de Antigravity. 100% seguro limpiar.",
            ),
            (
                "Antigravity CachedData (V8 Bundles)",
                "~/Library/Application Support/Antigravity/CachedData",
                "Caché App (Electron)",
                "Caché de compilación V8 de versiones de Antigravity. 100% seguro limpiar.",
            ),
            (
                "Antigravity GraphiteDawnCache (GPU)",
                "~/Library/Application Support/Antigravity/GraphiteDawnCache",
                "Caché GPU (Metal)",
                "Caché de shaders gráficos Dawn/Metal de Antigravity. 100% seguro limpiar.",
            ),
        ]
        for label, raw_p, c_tag, c_desc in special_app_support_caches:
            if self._cancel_requested:
                break
            fp = expand_home(raw_p)
            if os.path.isdir(fp) and not os.path.islink(fp):
                sz = fast_dir_size(fp, self.is_cancelled)
                if sz >= self.MIN_CACHE_LOG_BYTES:
                    items.append(
                        ScanItem(
                            id=str(uuid.uuid4()),
                            name=label,
                            path=fp,
                            abbreviated_path=abbreviate_path(fp),
                            size_bytes=sz,
                            module=ModuleType.CACHES_LOGS,
                            clean_strategy=CleanStrategy.DELETE_CONTENTS,
                            safety_level=SafetyLevel.SAFE,
                            safety_badge="🟢 100% Seguro borrar",
                            description=c_desc,
                            category_tag=c_tag,
                            selected=False,
                        )
                    )

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
            (
                "Grabaciones Antiguas de Navegador IA (browser_recordings)",
                "~/.gemini/antigravity/browser_recordings",
                "IA / Antigravity",
                "Grabaciones antiguas de sesiones de navegador en ~/.gemini/antigravity/browser_recordings. 100% seguro limpiar.",
            ),
            (
                "Caché de Navegador IA (Default Cache & Code Cache)",
                "~/.gemini/antigravity-browser-profile/Default/Cache",
                "IA / Browser Cache",
                "Caché temporal HTTP del perfil de navegador automatizado (~/.gemini/antigravity-browser-profile). 100% seguro limpiar.",
            ),
            (
                "Caché Bytecode Navegador IA (Default Code Cache)",
                "~/.gemini/antigravity-browser-profile/Default/Code Cache",
                "IA / Browser Cache",
                "Caché de código JS/WASM compilado del navegador automatizado. 100% seguro limpiar.",
            ),
            (
                "Caché Service Worker Navegador IA (Default)",
                "~/.gemini/antigravity-browser-profile/Default/Service Worker/CacheStorage",
                "IA / Browser Cache",
                "Almacenamiento en caché de Service Workers del navegador automatizado. 100% seguro limpiar.",
            ),
            (
                "Modelos de Optimización Chromium (optimization_guide_model_store)",
                "~/.gemini/antigravity-browser-profile/optimization_guide_model_store",
                "IA / Browser Cache",
                "Modelos temporales descargados por Chromium en el perfil de pruebas. 100% seguro limpiar.",
            ),
            (
                "Caché Extensiones CRX (component_crx_cache)",
                "~/.gemini/antigravity-browser-profile/component_crx_cache",
                "IA / Browser Cache",
                "Paquetes CRX en caché de componentes de Chromium. 100% seguro limpiar.",
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
            report(f"Calculando Desarrollo e IA: {label}...", 0.32 + 0.12 * ((idx + 1) / len(dev_targets)))
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

        # Obsolete full backup/duplicate directories in ~/.gemini & orphaned IntelliJ JDKs
        obsolete_dev_dirs = [
            (
                "Copia de Seguridad Duplicada (~/.gemini/antigravity-backup)",
                "~/.gemini/antigravity-backup",
                "IA / Backup Antiguo",
                (
                    "Copia de seguridad duplicada antigua (~945 MB) de ~/.gemini/antigravity. "
                    "100% seguro borrar; tu sesión activa actual reside en ~/.gemini/antigravity."
                ),
            ),
            (
                "Carpeta Duplicada de Versión Previa (~/.gemini/antigravity-ide)",
                "~/.gemini/antigravity-ide",
                "IA / Versión Antigua",
                (
                    "Datos duplicados antiguos (~957 MB) de cuando la app se llamaba Antigravity IDE. "
                    "100% seguro borrar; la app actual utiliza ~/.gemini/antigravity."
                ),
            ),
        ]
        for label, raw_p, d_tag, d_desc in obsolete_dev_dirs:
            if self._cancel_requested:
                break
            fp = expand_home(raw_p)
            if os.path.isdir(fp) and not os.path.islink(fp):
                sz = fast_dir_size(fp, self.is_cancelled)
                if sz >= self.MIN_CACHE_LOG_BYTES:
                    items.append(
                        ScanItem(
                            id=str(uuid.uuid4()),
                            name=label,
                            path=fp,
                            abbreviated_path=abbreviate_path(fp),
                            size_bytes=sz,
                            module=ModuleType.DEV_JUNK,
                            clean_strategy=CleanStrategy.DELETE_ITEM,
                            safety_level=SafetyLevel.SAFE,
                            safety_badge="🟢 100% Seguro borrar",
                            description=d_desc,
                            category_tag=d_tag,
                            selected=False,
                        )
                    )

        # Scan abandoned playgrounds inside ~/.gemini/antigravity/playground (e.g., polar-spirit node_modules)
        playground_root = expand_home("~/.gemini/antigravity/playground")
        if os.path.isdir(playground_root) and not self._cancel_requested:
            try:
                with os.scandir(playground_root) as entries:
                    for entry in entries:
                        if entry.name.startswith(".") or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                            continue
                        sz = fast_dir_size(entry.path, self.is_cancelled)
                        if sz >= self.ORPHAN_REMNANTS_THRESHOLD:
                            items.append(
                                ScanItem(
                                    id=str(uuid.uuid4()),
                                    name=f"Playground Temporal IA: {entry.name}",
                                    path=entry.path,
                                    abbreviated_path=abbreviate_path(entry.path),
                                    size_bytes=sz,
                                    module=ModuleType.DEV_JUNK,
                                    clean_strategy=CleanStrategy.DELETE_ITEM,
                                    safety_level=SafetyLevel.SAFE,
                                    safety_badge="🟢 100% Seguro borrar",
                                    description=(
                                        f"Proyecto temporal de pruebas en ~/.gemini/antigravity/playground/{entry.name} "
                                        "(incluye node_modules/.next). 100% seguro borrar si ya no usas ese experimento."
                                    ),
                                    category_tag="IA / Playground",
                                    selected=False,
                                )
                            )
            except (PermissionError, FileNotFoundError, OSError):
                pass

        # Scan orphaned IntelliJ IDEA JDKs in ~/Library/Java/JavaVirtualMachines
        user_jvms_dir = expand_home("~/Library/Java/JavaVirtualMachines")
        if os.path.isdir(user_jvms_dir) and not self._cancel_requested:
            intellij_installed = any(
                k in self.app_detector.installed_app_names
                for k in ("intellijidea", "pycharm", "androidstudio", "webstorm")
            )
            if not intellij_installed:
                try:
                    with os.scandir(user_jvms_dir) as entries:
                        for entry in entries:
                            if entry.name.startswith(".") or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                                continue
                            sz = fast_dir_size(entry.path, self.is_cancelled)
                            if sz >= self.ORPHAN_REMNANTS_THRESHOLD:
                                items.append(
                                    ScanItem(
                                        id=str(uuid.uuid4()),
                                        name=f"JDK Huérfano de IntelliJ ({entry.name})",
                                        path=entry.path,
                                        abbreviated_path=abbreviate_path(entry.path),
                                        size_bytes=sz,
                                        module=ModuleType.DEV_JUNK,
                                        clean_strategy=CleanStrategy.DELETE_ITEM,
                                        safety_level=SafetyLevel.SAFE,
                                        safety_badge="🟢 100% Seguro borrar",
                                        description=(
                                            f"Máquina virtual Java ({entry.name}) descargada en tu usuario por un IDE de JetBrains "
                                            "ya desinstalado (además ya dispones de JDK del sistema en /Library/Java)."
                                        ),
                                        category_tag="Java / JDK Huérfano",
                                        selected=False,
                                    )
                                )
                except (PermissionError, FileNotFoundError, OSError):
                    pass

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

        # Scan heavy reinstallable environments (venv, .venv, node_modules, .next) inside ~/Proyectos
        proyectos_root = expand_home("~/Proyectos")
        if os.path.isdir(proyectos_root) and not self._cancel_requested:
            report("Inspeccionando entornos virtuales y node_modules en ~/Proyectos...", 0.50)
            env_folder_names = {"venv", ".venv", "node_modules", ".next"}
            try:
                with os.scandir(proyectos_root) as proj_entries:
                    for proj in proj_entries:
                        if self._cancel_requested:
                            break
                        if proj.name.startswith(".") or proj.is_symlink() or not proj.is_dir(follow_symlinks=False):
                            continue
                        if proj.name.lower() == "aero":
                            continue
                        for env_name in env_folder_names:
                            cand = os.path.join(proj.path, env_name)
                            if os.path.isdir(cand) and not os.path.islink(cand):
                                sz = fast_dir_size(cand, self.is_cancelled)
                                if sz >= self.PROJECT_ENV_THRESHOLD:
                                    items.append(
                                        ScanItem(
                                            id=str(uuid.uuid4()),
                                            name=f"Entorno {env_name} en «{proj.name}»",
                                            path=cand,
                                            abbreviated_path=abbreviate_path(cand),
                                            size_bytes=sz,
                                            module=ModuleType.DEV_JUNK,
                                            clean_strategy=CleanStrategy.DELETE_ITEM,
                                            safety_level=SafetyLevel.REVIEW,
                                            safety_badge="🟡 Proyecto Local (Revisar)",
                                            description=(
                                                f"Dependencias instaladas ({env_name}) del proyecto «{proj.name}». "
                                                "Si ya no trabajas activamente en este proyecto, puedes borrarlo para ahorrar gigas "
                                                "(tu código fuente no se toca y siempre puedes reinstalarlo con pip/npm)."
                                            ),
                                            warning_label=(
                                                "🟡 ENTORNOS DE PROYECTO: No se marca automáticamente. "
                                                "Márcalo solo si tienes el proyecto archivado o no lo estás ejecutando."
                                            ),
                                            category_tag="Entorno de Proyecto",
                                            selected=False,
                                        )
                                    )
            except (PermissionError, FileNotFoundError, OSError):
                pass

        return items

    def _scan_module_3_app_remnants(
        self, report: Callable[[str, float], None]
    ) -> list[ScanItem]:
        """Module 3: Scans ~/Library/Application Support, ~/Library/Containers,
        plus known heavy hidden app-remnant folders in `~` (`.vscode`, `.android`, `.rvm`, etc.).
        Uses a 10 MB threshold for confirmed uninstalled/orphaned apps and 200 MB for active apps.
        """
        items: list[ScanItem] = []
        targets = [
            (expand_home("~/Library/Application Support"), "Application Support"),
            (expand_home("~/Library/Containers"), "Containers"),
        ]
        # Excluded here because Module 1 already handles them as 100% safe regenerable caches
        module_1_handled = {"com.adobe.dunamis", "coremlcache"}

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
                        and e.name.lower() not in module_1_handled
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
                    if size < self.ORPHAN_REMNANTS_THRESHOLD:
                        continue
                    safety_level, badge, desc, warning = self.app_detector.classify_app_remnant(
                        entry.name, tag
                    )
                    # Show all uninstalled/orphaned remnants >= 10 MB, and active apps > 200 MB
                    if safety_level == SafetyLevel.SAFE or size > self.APP_REMNANTS_THRESHOLD:
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

        # Also inspect known hidden app-data folders in ~ that uninstalled apps leave behind
        hidden_app_folders = [
            (".vscode", "~/.vscode", "Carpeta Oculta (~)"),
            (".android", "~/.android", "Carpeta Oculta (~)"),
            (".rvm", "~/.rvm", "Carpeta Oculta (~)"),
            (".ollama", "~/.ollama", "Carpeta Oculta (~)"),
            (".lmstudio", "~/.lmstudio", "Carpeta Oculta (~)"),
            (".cursor", "~/.cursor", "Carpeta Oculta (~)"),
            (".antigravity-ide", "~/.antigravity-ide", "Carpeta Oculta (~)"),
            (".codeium", "~/.codeium", "Carpeta Oculta (~)"),
            (".azure", "~/.azure", "Carpeta Oculta (~)"),
            (".stitch-mcp", "~/.stitch-mcp", "Carpeta Oculta (~)"),
            (".local/share/powershell", "~/.local/share/powershell", "Datos Locales (~/.local)"),
        ]
        for folder_key, raw_path, tag in hidden_app_folders:
            if self._cancel_requested:
                break
            full_path = expand_home(raw_path)
            if not os.path.isdir(full_path) or os.path.islink(full_path):
                continue
            size = fast_dir_size(full_path, self.is_cancelled)
            if size < self.ORPHAN_REMNANTS_THRESHOLD:
                continue
            safety_level, badge, desc, warning = self.app_detector.classify_app_remnant(
                folder_key, tag
            )
            if safety_level == SafetyLevel.SAFE or size > self.APP_REMNANTS_THRESHOLD:
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
