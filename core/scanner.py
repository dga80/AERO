import os
import subprocess
import uuid
from typing import Callable, Optional

from core.app_detector import AppDetector
from core.models import CleanStrategy, ModuleType, SafetyLevel, ScanItem, ScanSummary
from core.utils import (
    CREATE_NO_WINDOW,
    abbreviate_path,
    expand_home,
    fast_dir_size,
    get_entry_size,
    get_windows_trash_size,
)


class SystemDataScanner:
    """Multithreaded-friendly Windows NTFS System Data scanner covering 5 specialized modules."""

    MIN_CACHE_LOG_BYTES = 1 * 1024 * 1024         # 1 MB minimum for Caches/Logs
    APP_REMNANTS_THRESHOLD = 150 * 1024 * 1024    # 150 MB threshold for Module 3 AppData inspection
    DOWNLOADS_THRESHOLD = 250 * 1024 * 1024       # 250 MB threshold for Module 4 Downloads

    PRIORITY_EXTENSIONS = {".exe", ".msi", ".iso", ".zip", ".rar", ".7z", ".msix", ".appx"}

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

        report("Indexando programas instalados en Windows (Registro y Program Files)...", 0.05)
        self.app_detector.refresh_installed_apps()

        report("Escaneando Módulo 1: Cachés de Windows, Temp, Shaders y Navegadores...", 0.12)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_1_caches_and_logs(report))

        report("Escaneando Módulo 2: Basura de Desarrollo e IA (pip, uv, npm, HuggingFace, Gradle)...", 0.34)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_2_dev_junk(report))

        report("Escaneando Módulo 3: Restos de Programas en AppData (> 150 MB y carpetas ocultas)...", 0.56)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_3_app_remnants(report))

        report("Escaneando Módulo 4: Descargas Pesadas (> 250 MB) y Puntos de Restauración...", 0.80)
        tm_snapshots: list[str] = []
        if not self._cancel_requested:
            dl_items, tm_snapshots = self._scan_module_4_downloads_and_tm(report)
            all_items.extend(dl_items)

        report("Escaneando Módulo 5: Programas de Inicio y Optimización de Windows...", 0.90)
        if not self._cancel_requested:
            all_items.extend(self._scan_module_5_optimization())

        report("Calculando tamaño físico de la Papelera de reciclaje de Windows...", 0.96)
        trash_bytes = get_windows_trash_size() if not self._cancel_requested else 0

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
        """Module 1: Scans Windows Temp directories, CrashDumps, DirectX/GPU Shader Caches,
        WER error reports, Windows Update cache, and safe Browser Caches.
        """
        items: list[ScanItem] = []

        # 1. Subfolders & files inside %LOCALAPPDATA%\Temp (so %TEMP% root folder is preserved)
        user_temp = expand_home(r"%LOCALAPPDATA%\Temp")
        if os.path.isdir(user_temp) and not self._cancel_requested:
            report("Analizando archivos temporales de usuario (%TEMP%)...", 0.14)
            temp_size = fast_dir_size(user_temp, self.is_cancelled)
            if temp_size >= self.MIN_CACHE_LOG_BYTES:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name="Archivos Temporales de Usuario (%TEMP%)",
                        path=user_temp,
                        abbreviated_path=abbreviate_path(user_temp),
                        size_bytes=temp_size,
                        module=ModuleType.CACHES_LOGS,
                        clean_strategy=CleanStrategy.DELETE_CONTENTS,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 100% Seguro borrar",
                        description="Carpeta temporal de Windows (`AppData\\Local\\Temp`). Limpia todos los archivos temporales que no estén en uso activo.",
                        category_tag="Temporal Windows",
                        selected=False,
                    )
                )

        # 2. Known safe Windows System, GPU & Browser cache directories
        cache_targets = [
            (
                "Temporales del Sistema (C:\\Windows\\Temp)",
                r"%WINDIR%\Temp",
                "Temporal Sistema",
                "Archivos temporales antiguos generados por instaladores y servicios de Windows. 100% seguro limpiar.",
            ),
            (
                "Volcados de Cierres Inesperados (CrashDumps)",
                r"%LOCALAPPDATA%\CrashDumps",
                "Diagnóstico / Dump",
                "Archivos `.dmp` pesados creados cuando un programa se cierra por error. 100% seguro borrar.",
            ),
            (
                "Informes de Errores de Windows (WER)",
                r"%LOCALAPPDATA%\Microsoft\Windows\WER",
                "Registro (WER)",
                "Reportes antiguos de fallos de aplicaciones guardados por Windows Error Reporting. 100% seguro borrar.",
            ),
            (
                "Caché de Shaders DirectX (D3DSCache)",
                r"%LOCALAPPDATA%\D3DSCache",
                "Caché GPU / DirectX",
                "Shaders gráficos compilados por DirectX 12. Windows los regenera automáticamente al abrir juegos o apps.",
            ),
            (
                "Caché de Shaders NVIDIA (DXCache)",
                r"%LOCALAPPDATA%\NVIDIA\DXCache",
                "Caché GPU / NVIDIA",
                "Caché de shaders DirectX de tarjetas NVIDIA. 100% seguro limpiar.",
            ),
            (
                "Caché de Shaders NVIDIA (GLCache)",
                r"%LOCALAPPDATA%\NVIDIA\GLCache",
                "Caché GPU / NVIDIA",
                "Caché de shaders OpenGL de tarjetas NVIDIA. 100% seguro limpiar.",
            ),
            (
                "Caché de Shaders AMD (DxCache)",
                r"%LOCALAPPDATA%\AMD\DxCache",
                "Caché GPU / AMD",
                "Caché de shaders DirectX de gráficos AMD Radeon. 100% seguro limpiar.",
            ),
            (
                "Caché Temporal Web de Windows (INetCache)",
                r"%LOCALAPPDATA%\Microsoft\Windows\INetCache",
                "Caché Web",
                "Archivos temporales de componentes web de Windows. 100% seguro limpiar.",
            ),
            (
                "Descargas Antiguas de Windows Update",
                r"%WINDIR%\SoftwareDistribution\Download",
                "Windows Update",
                "Paquetes de actualización ya descargados por Windows Update. 100% seguro limpiar.",
            ),
            (
                "Google Chrome — Caché Web Temporal",
                r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache",
                "Navegador (Chrome)",
                "Imágenes y scripts temporales de páginas web en Chrome. No borra tus contraseñas, historial ni sesiones.",
            ),
            (
                "Google Chrome — Code Cache (JS/WASM)",
                r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Code Cache",
                "Navegador (Chrome)",
                "Código JavaScript compilado en caché por Chrome. 100% seguro borrar; no cierra tus sesiones.",
            ),
            (
                "Google Chrome — Service Worker Cache",
                r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Service Worker\CacheStorage",
                "Navegador (Chrome)",
                "Almacenamiento offline temporal de webs (Service Workers) en Chrome. 100% seguro borrar.",
            ),
            (
                "Microsoft Edge — Caché Web Temporal",
                r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache",
                "Navegador (Edge)",
                "Imágenes y archivos web temporales de Microsoft Edge. No borra contraseñas ni sesiones.",
            ),
            (
                "Microsoft Edge — Code Cache",
                r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Code Cache",
                "Navegador (Edge)",
                "Caché de código compilado de Microsoft Edge. 100% seguro borrar.",
            ),
            (
                "Microsoft Edge — Service Worker Cache",
                r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage",
                "Navegador (Edge)",
                "Caché pesada de Service Workers en Microsoft Edge. 100% seguro borrar.",
            ),
            (
                "Brave Browser — Caché Web Temporal",
                r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Cache",
                "Navegador (Brave)",
                "Archivos web temporales de Brave Browser. No borra tus datos ni sesiones.",
            ),
            (
                "Antigravity — Caché de GPU y Código",
                r"%APPDATA%\Antigravity\Cache",
                "Antigravity Cache",
                "Caché temporal de recursos de Antigravity IDE. 100% seguro limpiar.",
            ),
            (
                "VS Code — Caché Temporal (CachedData)",
                r"%APPDATA%\Code\CachedData",
                "VS Code Cache",
                "Bytecode en caché de versiones anteriores de Visual Studio Code. 100% seguro limpiar.",
            ),
            (
                "Discord — Caché Multimedia Temporal",
                r"%APPDATA%\discord\Cache",
                "Discord Cache",
                "Imágenes, GIFs y vídeos previsualizados en Discord. 100% seguro borrar; no cierra tu cuenta.",
            ),
            (
                "Spotify — Caché Temporal de Streaming",
                r"%LOCALAPPDATA%\Spotify\Data",
                "Spotify Cache",
                "Fragmentos de audio en caché de Spotify. 100% seguro limpiar.",
            ),
        ]

        total_targets = max(len(cache_targets), 1)
        for idx, (label, raw_path, tag, desc) in enumerate(cache_targets):
            if self._cancel_requested:
                break
            full_path = expand_home(raw_path)
            if not os.path.isdir(full_path):
                continue
            if idx % 3 == 0:
                report(f"Analizando {label}...", 0.16 + 0.16 * (idx / total_targets))
            size = fast_dir_size(full_path, self.is_cancelled)
            if size >= self.MIN_CACHE_LOG_BYTES:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name=label,
                        path=full_path,
                        abbreviated_path=abbreviate_path(full_path),
                        size_bytes=size,
                        module=ModuleType.CACHES_LOGS,
                        clean_strategy=CleanStrategy.DELETE_CONTENTS,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 100% Seguro borrar",
                        description=desc,
                        category_tag=tag,
                        selected=False,
                    )
                )

        return items

    def _scan_module_2_dev_junk(
        self, report: Callable[[str, float], None]
    ) -> list[ScanItem]:
        """Module 2: Verifies existence and calculates size of key developer & AI caches on Windows."""
        dev_targets = [
            (
                "pip Cache (Paquetes Python)",
                r"%LOCALAPPDATA%\pip\cache",
                "Python / pip",
                "Paquetes `.whl` antiguos descargados al instalar librerías de Python con pip. 100% seguro borrar.",
            ),
            (
                "uv Cache (AppData Local)",
                r"%LOCALAPPDATA%\uv\cache",
                "Python / uv",
                "Caché de ruedas y paquetes descargados por el gestor 'uv' en Windows. 100% seguro borrar; no afecta a tus `.venv`.",
            ),
            (
                "uv Cache (~/.cache/uv)",
                r"~/.cache/uv",
                "Python / uv",
                "Caché oculta de paquetes de 'uv' en tu carpeta de usuario. 100% seguro borrar.",
            ),
            (
                "NPM Cache (LocalAppData)",
                r"%LOCALAPPDATA%\npm-cache",
                "Node.js / npm",
                "Copias descargadas de paquetes antiguos de Node.js (npm). 100% seguro borrar; no afecta a `node_modules`.",
            ),
            (
                "NPM Cache (AppData Roaming)",
                r"%APPDATA%\npm-cache",
                "Node.js / npm",
                "Caché de paquetes descargados por npm en Roaming. 100% seguro borrar.",
            ),
            (
                "NPM Cache (~/.npm/_cacache)",
                r"~/.npm/_cacache",
                "Node.js / npm",
                "Caché oculta `_cacache` de Node.js. 100% seguro borrar.",
            ),
            (
                "NPX Cache (~/.npm/_npx)",
                r"~/.npm/_npx",
                "Node.js / npx",
                "Caché de paquetes y binarios ejecutados temporalmente con `npx`. 100% seguro borrar.",
            ),
            (
                "Bun Install Cache",
                r"~/.bun/install/cache",
                "JavaScript / Bun",
                "Caché local de paquetes y dependencias descargadas por Bun runtime. 100% seguro borrar.",
            ),
            (
                "pnpm Store Cache",
                r"%LOCALAPPDATA%\pnpm-store",
                "Node.js / pnpm",
                "Almacén en caché de paquetes de pnpm. 100% seguro borrar.",
            ),
            (
                "Yarn Cache",
                r"%LOCALAPPDATA%\Yarn\Cache",
                "Node.js / Yarn",
                "Caché local de paquetes descargados por Yarn. 100% seguro borrar.",
            ),
            (
                "HuggingFace Cache (Modelos IA)",
                r"~/.cache/huggingface",
                "IA / HuggingFace",
                "Pesos y modelos de Inteligencia Artificial descargados en caché (`~/.cache/huggingface`). 100% seguro borrar si no los usas.",
            ),
            (
                "PyTorch Hub / Torch Cache",
                r"~/.cache/torch",
                "IA / PyTorch",
                "Pesos preentrenados descargados en caché por PyTorch. 100% seguro borrar.",
            ),
            (
                "Playwright Browsers Cache",
                r"%LOCALAPPDATA%\ms-playwright",
                "Testing / Playwright",
                "Navegadores Chromium/Firefox/WebKit descargados para tests automatizados de Playwright. Seguro borrar si no los usas.",
            ),
            (
                "Puppeteer Cache",
                r"~/.cache/puppeteer",
                "Testing / Puppeteer",
                "Binarios de Chromium descargados en caché por Puppeteer. 100% seguro borrar.",
            ),
            (
                "NuGet Packages Cache (.NET)",
                r"~/.nuget/packages",
                ".NET / NuGet",
                "Caché global de paquetes NuGet de C# / .NET. Visual Studio los vuelve a descargar si compilas un proyecto que los pida.",
            ),
            (
                "Gradle Cache (Java / Android)",
                r"~/.gradle/caches",
                "Gradle",
                "Caché oculta de compilación y dependencias descargadas por Gradle. 100% seguro borrar.",
            ),
            (
                "Gradle Wrapper Distributions",
                r"~/.gradle/wrapper/dists",
                "Gradle",
                "Versiones antiguas del motor Gradle descargadas automáticamente. 100% seguro borrar.",
            ),
            (
                "Maven Repository Cache",
                r"~/.m2/repository",
                "Java / Maven",
                "Repositorio local en caché de librerías Java (Maven). 100% seguro borrar.",
            ),
            (
                "Cargo Cache (Rust)",
                r"~/.cargo/registry",
                "Rust / Cargo",
                "Caché de crates descargados por Rust Cargo. 100% seguro borrar.",
            ),
            (
                "Flutter / Dart Pub Cache",
                r"%LOCALAPPDATA%\Pub\Cache",
                "Flutter / Dart",
                "Caché de paquetes descargados por Flutter/Dart (`pub.dev`). 100% seguro borrar.",
            ),
            (
                "Go Build Cache",
                r"%LOCALAPPDATA%\go-build",
                "Go / Golang",
                "Caché de compilación incremental de Go. 100% seguro borrar.",
            ),
        ]

        items: list[ScanItem] = []
        seen_realpaths: set[str] = set()

        for idx, (label, raw_path, tag, desc) in enumerate(dev_targets):
            if self._cancel_requested:
                break
            full_path = expand_home(raw_path)
            if not os.path.exists(full_path):
                continue
            real_norm = os.path.normcase(os.path.realpath(full_path))
            if real_norm in seen_realpaths:
                continue
            seen_realpaths.add(real_norm)

            report(f"Calculando Desarrollo e IA: {label}...", 0.34 + 0.20 * ((idx + 1) / len(dev_targets)))
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
        return items

    def _scan_module_3_app_remnants(
        self, report: Callable[[str, float], None]
    ) -> list[ScanItem]:
        """Module 3: Scans %APPDATA% (Roaming), %LOCALAPPDATA% (Local), %USERPROFILE%\\AppData\\LocalLow (> 150 MB),
        plus known heavy hidden app-remnant folders in `~` (`.vscode`, `.android`, `.ollama`, etc.).
        """
        items: list[ScanItem] = []
        targets = [
            (expand_home(r"%APPDATA%"), "AppData\\Roaming"),
            (expand_home(r"%LOCALAPPDATA%"), "AppData\\Local"),
            (expand_home(r"~\AppData\LocalLow"), "AppData\\LocalLow"),
        ]

        excluded_appdata_folders = {
            "pip",
            "uv",
            "npm-cache",
            "pnpm-store",
            "yarn",
            "ms-playwright",
            "pub",
            "go-build",
            "crashdumps",
            "d3dscache",
            "temp",
        }

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
                        and e.name.lower() not in excluded_appdata_folders
                        and not self.app_detector.is_windows_system_folder(e.name)
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
                        0.56 + 0.18 * (idx / total_dirs),
                    )
                try:
                    size = fast_dir_size(entry.path, self.is_cancelled)
                    if size >= self.APP_REMNANTS_THRESHOLD:
                        safety_level, badge, desc, warning = self.app_detector.classify_app_remnant(
                            entry.name, tag
                        )
                        items.append(
                            ScanItem(
                                id=str(uuid.uuid4()),
                                name=f"{entry.name} ({tag})",
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

        # Also inspect known hidden app-data folders in ~ (> 150 MB) that uninstalled apps leave behind
        hidden_app_folders = [
            (".vscode", "~/.vscode", "Carpeta Oculta (~)"),
            (".android", "~/.android", "Carpeta Oculta (~)"),
            (".ollama", "~/.ollama", "Carpeta Oculta (~)"),
            (".lmstudio", "~/.lmstudio", "Carpeta Oculta (~)"),
            (".cursor", "~/.cursor", "Carpeta Oculta (~)"),
        ]
        for folder_key, raw_path, tag in hidden_app_folders:
            if self._cancel_requested:
                break
            full_path = expand_home(raw_path)
            if not os.path.isdir(full_path) or os.path.islink(full_path):
                continue
            size = fast_dir_size(full_path, self.is_cancelled)
            if size >= self.APP_REMNANTS_THRESHOLD:
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
        """Module 4: Scans ~/Downloads for files > 250 MB, checks C:\\Windows.old, and inspects Volume Shadow Copies."""
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
                            if size >= self.DOWNLOADS_THRESHOLD:
                                _, ext = os.path.splitext(entry.name.lower())
                                is_priority = ext in self.PRIORITY_EXTENSIONS
                                if is_priority:
                                    tag = f"Instalador / Archivo ({ext})"
                                    safety = SafetyLevel.SAFE
                                    badge = "🟢 Instalador antiguo (Seguro)"
                                    desc = (
                                        f"Instalador o archivo comprimido ({ext}) en tu carpeta Descargas. "
                                        "Si ya instalaste el programa o extrajiste el contenido, puedes borrarlo sin problema."
                                    )
                                else:
                                    tag = "Archivo Pesado"
                                    safety = SafetyLevel.REVIEW
                                    badge = "🟡 Archivo personal (Revisar)"
                                    desc = "Archivo o carpeta grande en Descargas. Verifica si aún lo necesitas antes de enviarlo a la Papelera."

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

        # Check for C:\Windows.old (leftover from major Windows feature updates)
        windows_old = r"C:\Windows.old"
        if os.path.isdir(windows_old) and not self._cancel_requested:
            report("Analizando copia antigua C:\\Windows.old...", 0.84)
            old_size = fast_dir_size(windows_old, self.is_cancelled)
            if old_size > 0:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name="Instalación Anterior de Windows (C:\\Windows.old)",
                        path=windows_old,
                        abbreviated_path=windows_old,
                        size_bytes=old_size,
                        module=ModuleType.DOWNLOADS_TM,
                        clean_strategy=CleanStrategy.DELETE_ITEM,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 Copia antigua (Seguro borrar)",
                        description="Carpeta de respaldo de una actualización anterior de Windows. Ocupa muchos gigabytes en C:\\.",
                        category_tag="Sistema Windows",
                        selected=False,
                    )
                )

        report("Verificando Puntos de Restauración y Copias Sombra (VSS)...", 0.86)
        snapshots = self._detect_windows_shadow_copies()
        return items, snapshots

    def _scan_module_5_optimization(self) -> list[ScanItem]:
        """Module 5: Scans Windows Startup folder, orphaned background updaters, and Explorer caches."""
        items: list[ScanItem] = []

        # 1. User Startup Folder (%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup)
        startup_dir = expand_home(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(startup_dir) and not self._cancel_requested:
            try:
                with os.scandir(startup_dir) as entries:
                    for entry in entries:
                        if entry.name.lower() == "desktop.ini" or entry.is_symlink():
                            continue
                        res = self.app_detector.inspect_startup_shortcut(entry.path)
                        if res is not None:
                            safety_level, badge, desc, warning = res
                            size = get_entry_size(entry.path)
                            items.append(
                                ScanItem(
                                    id=str(uuid.uuid4()),
                                    name=f"Inicio Automático: {entry.name}",
                                    path=entry.path,
                                    abbreviated_path=abbreviate_path(entry.path),
                                    size_bytes=max(size, 4096),
                                    module=ModuleType.OPTIMIZATION,
                                    clean_strategy=CleanStrategy.DELETE_ITEM,
                                    safety_level=safety_level,
                                    safety_badge=badge,
                                    description=desc,
                                    warning_label=warning,
                                    category_tag="Arranque Windows (RAM)",
                                    selected=False,
                                )
                            )
            except (PermissionError, FileNotFoundError, OSError):
                pass

        # 2. Check leftover GoogleUpdate if Chrome is not installed
        google_update_dir = expand_home(r"%LOCALAPPDATA%\Google\Update")
        if (
            os.path.isdir(google_update_dir)
            and self.app_detector._matches_installed("google chrome") is None
        ):
            sz = fast_dir_size(google_update_dir, self.is_cancelled)
            if sz > 0:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name="GoogleUpdate (Actualizador Fantasma)",
                        path=google_update_dir,
                        abbreviated_path=abbreviate_path(google_update_dir),
                        size_bytes=sz,
                        module=ModuleType.OPTIMIZATION,
                        clean_strategy=CleanStrategy.DELETE_ITEM,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 Programa desinstalado (Seguro borrar)",
                        description="Ejecutables en segundo plano de GoogleUpdate que quedaron tras desinstalar Chrome.",
                        warning_label="🟢 100% SEGURO BORRAR: Elimina el actualizador oculto de Google.",
                        category_tag="Proceso en Segundo Plano",
                        selected=False,
                    )
                )

        # 3. Windows WebCache / Icon & Thumbnail caches report
        explorer_dir = expand_home(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer")
        if os.path.isdir(explorer_dir) and not self._cancel_requested:
            thumb_bytes = 0
            try:
                with os.scandir(explorer_dir) as it:
                    for entry in it:
                        if entry.name.lower().startswith("thumbcache_") and entry.is_file():
                            thumb_bytes += get_entry_size(entry.path)
            except Exception:
                pass
            if thumb_bytes >= 5 * 1024 * 1024:
                items.append(
                    ScanItem(
                        id=str(uuid.uuid4()),
                        name="Caché de Miniaturas del Explorador (thumbcache)",
                        path=explorer_dir,
                        abbreviated_path=abbreviate_path(explorer_dir),
                        size_bytes=thumb_bytes,
                        module=ModuleType.OPTIMIZATION,
                        clean_strategy=CleanStrategy.DELETE_CONTENTS,
                        safety_level=SafetyLevel.SAFE,
                        safety_badge="🟢 100% Seguro borrar",
                        description="Bases de datos de miniaturas de carpetas antiguas del Explorador de Windows. Se regeneran solas.",
                        category_tag="Optimización Windows",
                        selected=False,
                    )
                )

        return items

    @staticmethod
    def _detect_windows_shadow_copies() -> list[str]:
        """Detects Windows System Restore / Volume Shadow Copies or Hibernation file (`C:\\hiberfil.sys`)."""
        notes: list[str] = []
        try:
            hiber = r"C:\hiberfil.sys"
            if os.path.exists(hiber):
                st = os.stat(hiber)
                if st.st_size > 0:
                    gb = st.st_size / (1024 ** 3)
                    notes.append(f"hiberfil.sys ({gb:.1f} GB)")
        except Exception:
            pass

        try:
            proc = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=CREATE_NO_WINDOW,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    clean = line.strip()
                    if "GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" in clean:
                        parts = clean.split("HarddiskVolumeShadowCopy")
                        notes.append(f"ShadowCopy#{parts[-1].strip()}")
        except Exception:
            pass

        return notes
