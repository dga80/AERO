import os
import plistlib
import re
import subprocess
from typing import Optional

from core.models import SafetyLevel
from core.utils import expand_home


class AppDetector:
    """Detects installed macOS applications across /Applications, ~/Applications, and Spotlight (mdfind),
    and classifies ~/Library/Application Support, ~/Library/Containers, hidden ~ folders,
    and ~/Library/LaunchAgents into Orphaned (Safe to delete), Active Installed App (Caution), or Apple System (Hidden).
    """

    APPLE_SYSTEM_FOLDERS = {
        "addressbook",
        "animoji",
        "app store",
        "audiocache.kcache",
        "caches",
        "callhistorydb",
        "callhistorytransactions",
        "cef",
        "clouddocs",
        "cloudkit",
        "codecplatform_mmpdec",
        "controlcenter",
        "coresimulator",
        "crashreporter",
        "differentialprivacy",
        "diskimages",
        "dock",
        "facetime",
        "familycircle",
        "fileprovider",
        "geoservices",
        "helper",
        "icloud",
        "instruments",
        "intelligenceflow",
        "knowledge",
        "log",
        "logs",
        "mediadownloadkit",
        "messages",
        "mobilesync",
        "music",
        "passkit",
        "photos",
        "quick look",
        "safari",
        "spotlight",
        "syncservices",
        "systempreferences",
        "ubiquity",
        "videosubscriptionsd",
        "wallpaper",
    }

    VENDOR_SUITE_PREFIXES: dict[str, tuple[str, list[str]]] = {
        "com.adobe.": (
            "Componente compartido de Adobe Creative Cloud / Photoshop / After Effects.",
            [
                "adobe photoshop 2024",
                "adobe after effects 2024",
                "adobe creative cloud",
                "adobe acrobat dc",
                "adobe media encoder 2021",
            ],
        ),
        "com.microsoft.defender": (
            "Datos de Microsoft Defender.",
            ["microsoft defender shim", "microsoft defender"],
        ),
        "com.seriflabs.": (
            "Componente de la suite de diseño Affinity.",
            ["affinity"],
        ),
    }

    # Tuple format: (description, exact_app_names, exact_bundle_ids)
    KNOWN_FOLDERS_GUIDE: dict[str, tuple[str, list[str], list[str]]] = {
        "com.docker.docker": (
            "Disco virtual e imágenes de Docker Desktop (Docker.raw).",
            ["docker", "docker desktop"],
            ["com.docker.docker"],
        ),
        "docker desktop": (
            "Datos y configuraciones de Docker Desktop.",
            ["docker", "docker desktop"],
            ["com.docker.docker"],
        ),
        "code": (
            "Datos de Microsoft Visual Studio Code (extensiones, estado y copias locales).",
            ["visual studio code", "visual studio code - insiders"],
            ["com.microsoft.vscode", "com.microsoft.vscodeinsiders"],
        ),
        ".vscode": (
            "Carpeta oculta ~/.vscode con todas las extensiones descargadas de Visual Studio Code.",
            ["visual studio code", "visual studio code - insiders"],
            ["com.microsoft.vscode", "com.microsoft.vscodeinsiders"],
        ),
        ".android": (
            "Carpeta oculta ~/.android con imágenes de emuladores (AVD) y cachés de Android Studio.",
            ["android studio"],
            ["com.google.android.studio"],
        ),
        ".rvm": (
            "Carpeta oculta ~/.rvm con versiones antiguas de Ruby (Ruby Version Manager).",
            [],
            [],
        ),
        ".ollama": (
            "Carpeta oculta ~/.ollama con modelos de IA locales de Ollama.",
            ["ollama"],
            ["com.electron.ollama"],
        ),
        ".lmstudio": (
            "Carpeta oculta ~/.lmstudio con modelos de IA locales de LM Studio.",
            ["lm studio"],
            ["ai.elementlabs.lmstudio"],
        ),
        ".cursor": (
            "Carpeta oculta ~/.cursor con extensiones de Cursor IDE.",
            ["cursor"],
            ["com.todesktop.230313mzl4w4u92"],
        ),
        "antigravity": (
            "Datos de sesión, artefactos e índices de Antigravity.",
            ["antigravity"],
            ["com.google.antigravity"],
        ),
        "antigravity ide": (
            "Configuración y cachés de trabajo de Antigravity IDE.",
            ["antigravity", "antigravity ide"],
            ["com.google.antigravity"],
        ),
        "google": (
            "Perfiles, cachés y datos locales de Google Chrome.",
            ["google chrome"],
            ["com.google.chrome"],
        ),
        "firefox": (
            "Perfiles y datos de navegación de Mozilla Firefox.",
            ["firefox"],
            ["org.mozilla.firefox"],
        ),
        "mozilla": (
            "Datos de soporte de aplicaciones de Mozilla (Firefox).",
            ["firefox"],
            ["org.mozilla.firefox"],
        ),
        "microsoft edge": (
            "Perfiles y datos locales del navegador Microsoft Edge.",
            ["microsoft edge"],
            ["com.microsoft.edgemac"],
        ),
        "adobe": (
            "Componentes compartidos, cachés de medios y ajustes de Adobe Creative Cloud / Photoshop / After Effects.",
            [
                "adobe photoshop 2024",
                "adobe after effects 2024",
                "adobe creative cloud",
                "adobe acrobat dc",
                "adobe media encoder 2021",
            ],
            ["com.adobe.acc.adobeccsdesktop", "com.adobe.photoshop", "com.adobe.aftereffects"],
        ),
        "affinity": (
            "Pinceles, activos y datos de configuración de Affinity.",
            ["affinity", "affinity designer 2", "affinity photo 2", "affinity publisher 2"],
            ["com.seriflabs.affinity"],
        ),
        "comfy desktop": (
            "Modelos de IA, nodos y entorno de ComfyUI Desktop.",
            ["comfy", "comfy desktop", "comfyui"],
            ["org.comfy.comfyui"],
        ),
        "tts": (
            "Modelos descargados de conversión de Texto a Voz (Text-To-Speech / Coqui TTS).",
            ["tts", "coqui tts"],
            [],
        ),
        "net.metaquotes.wine.metatrader5": (
            "Entorno emulado Wine y datos de la plataforma bursátil MetaTrader 5.",
            ["metatrader 5", "metatrader5"],
            ["net.metaquotes.wine.metatrader5"],
        ),
        "pi network": (
            "Datos locales y nodo de la aplicación Pi Network.",
            ["pi network"],
            ["com.pinetwork.desktop"],
        ),
        "com.wondershare.installer": (
            "Archivos residuales del instalador de Wondershare.",
            ["wondershare filmora", "wondershare filmora 10", "filmora"],
            ["com.wondershare.filmora", "com.wondershare.installer"],
        ),
        "wondershare filmora 10": (
            "Paquetes de efectos, medios renderizados y datos de Wondershare Filmora 10.",
            ["wondershare filmora", "wondershare filmora 10", "filmora"],
            ["com.wondershare.filmora"],
        ),
        "spotify": (
            "Caché de canciones offline y datos de la app de escritorio Spotify.",
            ["spotify"],
            ["com.spotify.client"],
        ),
        "tabnine": (
            "Modelos locales de autocompletado de código de TabNine.",
            ["tabnine"],
            [],
        ),
        "mongodb compass": (
            "Conexiones guardadas e historial de MongoDB Compass.",
            ["mongodb compass"],
            ["com.mongodb.compass"],
        ),
        "jetbrains": (
            "Plugins, índices y ajustes de IDEs de JetBrains (PyCharm, IntelliJ, WebStorm).",
            ["pycharm", "intellij idea", "webstorm", "goland", "clion", "android studio"],
            ["com.jetbrains.pycharm", "com.jetbrains.intellij"],
        ),
        "flipper": (
            "Datos de depuración de Flipper Desktop.",
            ["flipper"],
            ["com.facebook.flipper"],
        ),
        "artcraft launcher": (
            "Archivos y recursos descargados por ArtCraft Launcher.",
            ["artcraft launcher"],
            [],
        ),
        "gridcraft": (
            "Datos locales y proyectos de GridCraft.",
            ["gridcraft"],
            [],
        ),
        "wordcraft": (
            "Datos locales de WordCraft.",
            ["wordcraft"],
            [],
        ),
        "audacity": (
            "Complementos y datos temporales de Audacity.",
            ["audacity", "audacity 4"],
            ["org.audacityteam.audacity"],
        ),
        "sourcetree": (
            "Configuración de repositorios de Atlassian Sourcetree.",
            ["sourcetree"],
            ["com.torusknot.sourcetreenotmas"],
        ),
    }

    def __init__(self) -> None:
        self.installed_bundle_ids: set[str] = set()
        self.installed_app_names: set[str] = set()
        self.bundle_to_app_name: dict[str, str] = {}
        self.refresh_installed_apps()

    @staticmethod
    def _normalize(text: str) -> str:
        """Lowercases and strips non-alphanumeric chars for exact comparison."""
        return re.sub(r"[^a-z0-9]", "", text.lower())

    def refresh_installed_apps(self) -> None:
        """Scans /Applications, ~/Applications, and queries Spotlight for installed .app bundles."""
        self.installed_bundle_ids.clear()
        self.installed_app_names.clear()
        self.bundle_to_app_name.clear()

        app_roots = [
            "/Applications",
            expand_home("~/Applications"),
            "/System/Applications",
        ]

        for root in app_roots:
            if not os.path.isdir(root):
                continue
            self._scan_apps_dir(root, depth=0)

        try:
            proc = subprocess.run(
                [
                    "mdfind",
                    "-onlyin",
                    "/Applications",
                    "kMDItemContentType == 'com.apple.application-bundle'",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    p = line.strip()
                    if p.endswith(".app") and os.path.isdir(p):
                        app_title = os.path.basename(p)[:-4]
                        self._register_app_bundle(p, app_title)
        except Exception:
            pass

    def _scan_apps_dir(self, directory: str, depth: int) -> None:
        if depth > 2:
            return
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.lower().endswith(".app"):
                                self._register_app_bundle(entry.path, entry.name[:-4])
                            else:
                                norm_folder = self._normalize(entry.name)
                                if len(norm_folder) >= 3:
                                    self.installed_app_names.add(norm_folder)
                                self._scan_apps_dir(entry.path, depth + 1)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, FileNotFoundError, OSError):
            pass

    def _register_app_bundle(self, app_path: str, raw_app_name: str) -> None:
        norm_name = self._normalize(raw_app_name)
        if norm_name:
            self.installed_app_names.add(norm_name)
        stripped_version = re.sub(r"\s+\d+(\.\d+)*$", "", raw_app_name).strip()
        norm_stripped = self._normalize(stripped_version)
        if norm_stripped:
            self.installed_app_names.add(norm_stripped)

        plist_path = os.path.join(app_path, "Contents", "Info.plist")
        if os.path.isfile(plist_path):
            try:
                with open(plist_path, "rb") as f:
                    plist_data = plistlib.load(f)
                bundle_id = plist_data.get("CFBundleIdentifier")
                if isinstance(bundle_id, str) and bundle_id.strip():
                    bid_lower = bundle_id.strip().lower()
                    self.installed_bundle_ids.add(bid_lower)
                    self.bundle_to_app_name[bid_lower] = raw_app_name
            except Exception:
                pass

    def is_apple_system_folder(self, folder_name: str) -> bool:
        """Returns True if the folder is an essential macOS / Apple system component."""
        lower = folder_name.lower().strip()
        if (
            lower.startswith("com.apple.")
            or lower.startswith("group.com.apple.")
            or lower.startswith("system.")
        ):
            return True
        if lower in self.APPLE_SYSTEM_FOLDERS:
            return True
        return False

    def classify_app_remnant(
        self, folder_name: str, source_tag: str
    ) -> tuple[SafetyLevel, str, str, str]:
        """Classifies a folder from Application Support, Containers, or ~ hidden folders.
        
        Returns:
            (safety_level, safety_badge, description, warning_label)
        """
        lower_name = folder_name.lower().strip()
        norm_name = self._normalize(folder_name)

        # 0. Check Vendor Suite Prefixes (e.g., com.adobe.* belongs to Adobe if any Adobe app is installed)
        for prefix, (suite_desc, suite_apps) in self.VENDOR_SUITE_PREFIXES.items():
            if lower_name.startswith(prefix):
                suite_installed = any(
                    self._normalize(a) in self.installed_app_names for a in suite_apps
                )
                if suite_installed:
                    return (
                        SafetyLevel.INSTALLED_APP,
                        "🔴 App en uso (No borrar)",
                        suite_desc,
                        "🔴 COMPONENTE EN USO: Pertenece a una suite instalada en tu Mac (ej. Adobe). No se recomienda borrarlo.",
                    )

        # 1. Check Known Folders Guide with strict exact matching on App Names and Bundle IDs
        known_desc: Optional[str] = None
        known_installed: Optional[bool] = None
        if lower_name in self.KNOWN_FOLDERS_GUIDE:
            known_desc, exact_apps, exact_bundles = self.KNOWN_FOLDERS_GUIDE[lower_name]
            has_app_match = any(
                self._normalize(app_candidate) in self.installed_app_names
                for app_candidate in exact_apps
            )
            has_bundle_match = any(
                b_candidate.lower() in self.installed_bundle_ids
                for b_candidate in exact_bundles
            )
            known_installed = has_app_match or has_bundle_match

        # 2. Check exact Bundle ID or exact App Name match for unlisted folders
        is_installed = False
        matched_app_label = folder_name

        if known_installed is not None:
            is_installed = known_installed
        else:
            if lower_name in self.installed_bundle_ids:
                is_installed = True
                matched_app_label = self.bundle_to_app_name.get(lower_name, folder_name)
            else:
                for bid, app_title in self.bundle_to_app_name.items():
                    if lower_name == bid or lower_name.startswith(bid + "."):
                        is_installed = True
                        matched_app_label = app_title
                        break

            if not is_installed and norm_name in self.installed_app_names:
                is_installed = True

        # 3. Build clear, human-friendly Spanish explanation
        if is_installed:
            desc = (
                known_desc
                or f"Datos activos de «{matched_app_label}» (instalada actualmente en /Applications)."
            )
            warning = (
                "🔴 APP INSTALADA: No borres esta carpeta si usas este programa, "
                "para conservar tus datos y configuraciones."
            )
            return (
                SafetyLevel.INSTALLED_APP,
                "🔴 App en uso (No borrar)",
                desc,
                warning,
            )
        else:
            if known_desc:
                desc = f"{known_desc} (App ya desinstalada de tu Mac)."
            else:
                desc = (
                    f"No tienes «{folder_name}» en /Applications. "
                    "Son restos antiguos de una app desinstalada."
                )
            warning = (
                "🟢 RESTO HUÉRFANO (SEGURO BORRAR): Esta app ya no está instalada en tu Mac. "
                "Puedes enviarla a la Papelera sin ningún riesgo."
            )
            return (
                SafetyLevel.SAFE,
                "🟢 App desinstalada (Seguro borrar)",
                desc,
                warning,
            )

    def inspect_launch_agent(self, plist_path: str) -> Optional[tuple[SafetyLevel, str, str, str]]:
        """Inspects a ~/Library/LaunchAgents/*.plist file.
        
        Returns None if it's a valid, active agent for an installed app.
        Returns (SafetyLevel, badge, description, warning) if it is broken/orphaned or belongs to an uninstalled app.
        """
        fname = os.path.basename(plist_path)
        lower_fname = fname.lower()
        if lower_fname.startswith("com.apple."):
            return None

        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            return None

        prog = data.get("Program")
        if not prog:
            args = data.get("ProgramArguments")
            if isinstance(args, list) and len(args) > 0 and isinstance(args[0], str):
                prog = args[0]

        if not prog or not isinstance(prog, str):
            return None

        # Case 1: The executable binary this LaunchAgent tries to run no longer exists on disk!
        if not os.path.exists(prog):
            return (
                SafetyLevel.SAFE,
                "🟢 Proceso roto (Seguro borrar)",
                f"Agente de inicio roto: intenta ejecutar «{prog}», pero ese archivo ya no existe en tu Mac.",
                "🟢 100% SEGURO BORRAR: Evita que macOS intente arrancar en segundo plano un programa que ya borraste.",
            )

        # Case 2: Microsoft EdgeUpdater running in background when Microsoft Edge is uninstalled
        if "edgeupdater" in lower_fname or "edgeupdater" in prog.lower():
            if "microsoftedge" not in self.installed_app_names:
                return (
                    SafetyLevel.SAFE,
                    "🟢 App desinstalada (Seguro borrar)",
                    "Actualizador en segundo plano de Microsoft Edge (navegador ya desinstalado de tu Mac).",
                    "🟢 100% SEGURO BORRAR: Detiene el proceso fantasma de actualización de Microsoft Edge.",
                )

        # Case 3: Snap Camera AssistantService (discontinued software) when Snap Camera.app is uninstalled
        if "com.snap." in lower_fname or "snapcamera" in prog.lower():
            if "snapcamera" not in self.installed_app_names:
                return (
                    SafetyLevel.SAFE,
                    "🟢 App desinstalada (Seguro borrar)",
                    "Servicio en segundo plano de Snap Camera (aplicación desinstalada/descontinuada).",
                    "🟢 100% SEGURO BORRAR: Evita que el servicio fantasma de Snap Camera consuma RAM al iniciar el Mac.",
                )

        return None
