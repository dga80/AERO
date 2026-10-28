import os
import re
from typing import Optional

from core.models import SafetyLevel
from core.utils import expand_home

try:
    import winreg
except ImportError:
    winreg = None  # type: ignore


class AppDetector:
    """Detects installed Windows applications across Registry Uninstall keys,
    Program Files, Program Files (x86), %LOCALAPPDATA%\\Programs, and Start Menu,
    and classifies %APPDATA% (Roaming), %LOCALAPPDATA% (Local), and hidden ~ folders
    into Orphaned (Safe to delete), Active Installed App (Caution), or Windows System (Hidden).
    """

    WINDOWS_SYSTEM_FOLDERS = {
        "application data",
        "comms",
        "connecteddevicesplatform",
        "crashdumps",
        "d3dscache",
        "deployment",
        "diagnostics",
        "elevateddiagnostics",
        "fontcache",
        "history",
        "iconcache.db",
        "identities",
        "internet explorer",
        "local",
        "locallow",
        "Low",
        "microsoft",
        "microsoftedge",
        "onedrive",
        "packages",
        "peerdistrepub",
        "placeholdertilelogofolder",
        "programs",
        "publishers",
        "roaming",
        "roamingtilecache",
        "start menu",
        "temp",
        "temporary internet files",
        "tiledataLayer",
        "twain_32",
        "virtualstore",
        "windows",
        "windows defender",
        "windows mail",
        "windows media player",
        "windows nt",
        "windows photo viewer",
        "windows portable devices",
        "windows security",
        "windows sidebar",
        "windowsapps",
        "windowspowershell",
    }

    VENDOR_SUITE_PREFIXES: dict[str, tuple[str, list[str]]] = {
        "adobe": (
            "Componente compartido de Adobe Creative Cloud / Photoshop / Premiere / Acrobat.",
            [
                "adobe",
                "adobe creative cloud",
                "adobe photoshop",
                "adobe premiere",
                "adobe after effects",
                "adobe acrobat",
                "acrobat",
            ],
        ),
        "jetbrains": (
            "Plugins, índices y cachés de IDEs de JetBrains (PyCharm, IntelliJ, WebStorm).",
            ["pycharm", "intellij", "webstorm", "goland", "clion", "rider", "jetbrains"],
        ),
        "autodesk": (
            "Componentes y licencias de Autodesk (AutoCAD, Revit, Maya, Fusion).",
            ["autodesk", "autocad", "revit", "maya", "fusion 360", "3ds max"],
        ),
        "nvidia": (
            "Controladores gráficos, shaders y telemetría de NVIDIA.",
            ["nvidia", "geforce experience", "nvidia app", "nvidia graphics driver"],
        ),
        "amd": (
            "Controladores gráficos y caché de shaders de AMD Radeon.",
            ["amd", "amd software", "radeon"],
        ),
        "intel": (
            "Controladores y perfiles de hardware Intel.",
            ["intel", "intel graphics"],
        ),
    }

    # Tuple format: (description, candidate_app_names)
    KNOWN_FOLDERS_GUIDE: dict[str, tuple[str, list[str]]] = {
        "docker": (
            "Imágenes virtuales WSL2/Hyper-V y datos de Docker Desktop (`ext4.vhdx`).",
            ["docker", "docker desktop"],
        ),
        "docker desktop": (
            "Datos y configuraciones de Docker Desktop.",
            ["docker", "docker desktop"],
        ),
        "code": (
            "Datos de Microsoft Visual Studio Code (extensiones, estado y copias locales).",
            ["visual studio code", "microsoft visual studio code", "code"],
        ),
        ".vscode": (
            "Carpeta oculta ~/.vscode con todas las extensiones descargadas de Visual Studio Code.",
            ["visual studio code", "microsoft visual studio code", "code"],
        ),
        ".android": (
            "Carpeta oculta ~/.android con imágenes de emuladores (AVD) y cachés de Android Studio.",
            ["android studio"],
        ),
        "android": (
            "SDK de Android (`AppData\\Local\\Android\\Sdk`), imágenes de sistema y herramientas.",
            ["android studio"],
        ),
        ".ollama": (
            "Carpeta ~/.ollama con modelos de IA locales descargados por Ollama.",
            ["ollama"],
        ),
        "ollama": (
            "Binarios y registros locales de Ollama.",
            ["ollama"],
        ),
        ".lmstudio": (
            "Carpeta ~/.lmstudio con modelos LLM locales de LM Studio.",
            ["lm studio", "lm-studio"],
        ),
        "lm-studio": (
            "Datos de aplicación de LM Studio.",
            ["lm studio", "lm-studio"],
        ),
        ".cursor": (
            "Carpeta oculta ~/.cursor con extensiones de Cursor IDE.",
            ["cursor"],
        ),
        "cursor": (
            "Datos, índices y cachés de trabajo de Cursor IDE.",
            ["cursor"],
        ),
        "antigravity": (
            "Datos de sesión, artefactos e índices de Antigravity IDE.",
            ["antigravity", "google antigravity"],
        ),
        "google": (
            "Perfiles, cachés y datos locales de Google Chrome / Google Drive.",
            ["google chrome", "chrome", "google drive"],
        ),
        "mozilla": (
            "Perfiles y datos de navegación de Mozilla Firefox.",
            ["mozilla firefox", "firefox"],
        ),
        "bravesoftware": (
            "Perfiles y datos locales del navegador Brave.",
            ["brave", "brave browser"],
        ),
        "opera software": (
            "Perfiles y datos locales del navegador Opera / Opera GX.",
            ["opera", "opera gx"],
        ),
        "vivaldi": (
            "Perfiles y datos locales del navegador Vivaldi.",
            ["vivaldi"],
        ),
        "spotify": (
            "Caché de canciones offline y datos de la app de escritorio Spotify.",
            ["spotify"],
        ),
        "discord": (
            "Caché multimedia, módulos y sesión de Discord.",
            ["discord"],
        ),
        "slack": (
            "Archivos adjuntos en caché y sesiones de Slack.",
            ["slack"],
        ),
        "telegram desktop": (
            "Fotos, vídeos y archivos descargados automáticamente en Telegram Desktop.",
            ["telegram", "telegram desktop"],
        ),
        "whatsapp": (
            "Datos y medios descargados de WhatsApp Desktop.",
            ["whatsapp"],
        ),
        "zoom": (
            "Datos, grabaciones temporales y binarios de Zoom Workplace.",
            ["zoom", "zoom workplace"],
        ),
        "steam": (
            "Caché de navegador, shaders e interfaz de Steam.",
            ["steam"],
        ),
        "epicgameslauncher": (
            "Caché de tienda, manifiestos y logs de Epic Games Launcher.",
            ["epic games launcher", "epic games"],
        ),
        "ubisoft game launcher": (
            "Caché y datos de Ubisoft Connect.",
            ["ubisoft connect", "ubisoft game launcher"],
        ),
        "electronic arts": (
            "Datos y caché de EA App / Origin.",
            ["ea app", "origin", "electronic arts"],
        ),
        "riot games": (
            "Clientes y registros de Riot Games (League of Legends / Valorant).",
            ["riot client", "riot games", "valorant", "league of legends"],
        ),
        "obs-studio": (
            "Escenas, perfiles y plugins de OBS Studio.",
            ["obs studio", "obs-studio"],
        ),
        "capcut": (
            "Proyectos, cachés de vídeo renderizado y efectos de CapCut Desktop.",
            ["capcut"],
        ),
        "wondershare": (
            "Paquetes de efectos, medios renderizados y datos de Wondershare Filmora.",
            ["wondershare filmora", "filmora", "wondershare"],
        ),
        "postman": (
            "Colecciones locales e historial de peticiones de Postman.",
            ["postman"],
        ),
        "insomnia": (
            "Datos locales de pruebas de API de Insomnia.",
            ["insomnia"],
        ),
        "mongodb compass": (
            "Conexiones guardadas e historial de MongoDB Compass.",
            ["mongodb compass"],
        ),
        "dbeaverdata": (
            "Controladores JDBC, conexiones y scripts SQL de DBeaver.",
            ["dbeaver"],
        ),
        "unity": (
            "Asset Store cache y paquetes descargados de Unity Hub / Editor.",
            ["unity", "unity hub"],
        ),
        "unrealengine": (
            "DerivedDataCache y shaders compilados de Unreal Engine.",
            ["unreal engine", "epic games launcher"],
        ),
        "blender foundation": (
            "Complementos (Add-ons) y configuración de versiones de Blender.",
            ["blender"],
        ),
        "audacity": (
            "Complementos y datos de recuperación de proyectos de Audacity.",
            ["audacity"],
        ),
        "vlc": (
            "Caché de carátulas y preferencias de VLC media player.",
            ["vlc media player", "vlc"],
        ),
        "anydesk": (
            "Configuración y miniaturas de sesiones remotas de AnyDesk.",
            ["anydesk"],
        ),
        "teamviewer": (
            "Registros y datos de conexión remota de TeamViewer.",
            ["teamviewer"],
        ),
        "notion": (
            "Base de datos local offline y caché de recursos de Notion.",
            ["notion"],
        ),
        "obsidian": (
            "Caché de índices y configuración de bóvedas de Obsidian.",
            ["obsidian"],
        ),
        "comfyui": (
            "Modelos de IA, nodos y entorno de ComfyUI Desktop.",
            ["comfyui", "comfy desktop"],
        ),
    }

    def __init__(self) -> None:
        self.installed_app_names: set[str] = set()
        self.installed_publishers: set[str] = set()
        self.raw_installed_titles: dict[str, str] = {}
        self.refresh_installed_apps()

    @staticmethod
    def _normalize(text: str) -> str:
        """Lowercases and strips non-alphanumeric chars for fuzzy-safe comparison."""
        return re.sub(r"[^a-z0-9]", "", text.lower())

    def refresh_installed_apps(self) -> None:
        """Scans Windows Registry Uninstall keys, Program Files, %LOCALAPPDATA%\\Programs, and Start Menu."""
        self.installed_app_names.clear()
        self.installed_publishers.clear()
        self.raw_installed_titles.clear()

        # Always mark current active environment tools as installed
        for builtin in ("Antigravity", "Google Antigravity", "Python", "Windows Explorer", "Microsoft Edge"):
            self._register_app_name(builtin)

        # 1. Scan Windows Registry Uninstall keys (HKLM 64-bit, HKLM 32-bit WOW64, HKCU)
        if winreg is not None:
            reg_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]
            for hive, subkey_path in reg_paths:
                try:
                    with winreg.OpenKey(hive, subkey_path) as key:
                        num_subkeys = winreg.QueryInfoKey(key)[0]
                        for i in range(num_subkeys):
                            try:
                                sub_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, sub_name) as subkey:
                                    try:
                                        disp_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                        if isinstance(disp_name, str) and disp_name.strip():
                                            self._register_app_name(disp_name.strip())
                                    except OSError:
                                        pass
                                    try:
                                        publisher, _ = winreg.QueryValueEx(subkey, "Publisher")
                                        if isinstance(publisher, str) and publisher.strip():
                                            norm_pub = self._normalize(publisher)
                                            if len(norm_pub) >= 3:
                                                self.installed_publishers.add(norm_pub)
                                    except OSError:
                                        pass
                                    try:
                                        inst_loc, _ = winreg.QueryValueEx(subkey, "InstallLocation")
                                        if isinstance(inst_loc, str) and inst_loc.strip():
                                            loc_base = os.path.basename(inst_loc.rstrip("\\/"))
                                            if len(loc_base) >= 3:
                                                self._register_app_name(loc_base)
                                    except OSError:
                                        pass
                            except OSError:
                                continue
                except OSError:
                    continue

        # 2. Scan standard Windows program installation directories
        app_roots = [
            expand_home(r"%ProgramFiles%"),
            expand_home(r"%ProgramFiles(x86)%"),
            expand_home(r"%LOCALAPPDATA%\Programs"),
            expand_home(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs"),
            expand_home(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs"),
        ]
        for root in app_roots:
            if os.path.isdir(root):
                self._scan_program_dir(root, depth=0)

    def _scan_program_dir(self, directory: str, depth: int) -> None:
        if depth > 2:
            return
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            # Check if directory isn't empty before registering as installed
                            has_files = False
                            try:
                                with os.scandir(entry.path) as sub_it:
                                    for _ in sub_it:
                                        has_files = True
                                        break
                            except OSError:
                                pass
                            if has_files:
                                self._register_app_name(entry.name)
                                if depth < 1:
                                    self._scan_program_dir(entry.path, depth + 1)
                        elif entry.name.lower().endswith(".lnk") or entry.name.lower().endswith(".exe"):
                            stem = os.path.splitext(entry.name)[0]
                            if not any(w in stem.lower() for w in ("uninstall", "desinstalar", "unins000")):
                                self._register_app_name(stem)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, FileNotFoundError, OSError):
            pass

    def _register_app_name(self, raw_name: str) -> None:
        norm_full = self._normalize(raw_name)
        if len(norm_full) >= 2:
            self.installed_app_names.add(norm_full)
            self.raw_installed_titles.setdefault(norm_full, raw_name)

        # Also strip trailing version numbers / architecture tags like "(64-bit)", "v2.4", "2024"
        cleaned = re.sub(
            r"(\s*\((?:64-bit|32-bit|x64|x86|user)\)|\s+v?\d+(\.\d+)*)+$",
            "",
            raw_name,
            flags=re.IGNORECASE,
        ).strip()
        norm_cleaned = self._normalize(cleaned)
        if len(norm_cleaned) >= 2:
            self.installed_app_names.add(norm_cleaned)
            self.raw_installed_titles.setdefault(norm_cleaned, cleaned)

    def is_windows_system_folder(self, folder_name: str) -> bool:
        """Returns True if the folder is an essential Windows / Microsoft system component."""
        lower = folder_name.lower().strip()
        if lower in self.WINDOWS_SYSTEM_FOLDERS:
            return True
        if (
            lower.startswith("microsoft.")
            or lower.startswith("windows.")
            or lower.startswith("{")
        ):
            return True
        return False

    def _matches_installed(self, candidate: str) -> Optional[str]:
        """Checks if `candidate` matches any installed application name."""
        norm_cand = self._normalize(candidate)
        if not norm_cand:
            return None
        if norm_cand in self.installed_app_names:
            return self.raw_installed_titles.get(norm_cand, candidate)
        for inst_norm, raw_title in self.raw_installed_titles.items():
            if len(norm_cand) >= 4 and (
                inst_norm.startswith(norm_cand) or norm_cand.startswith(inst_norm)
            ):
                if len(inst_norm) >= 4:
                    return raw_title
        return None

    def classify_app_remnant(
        self, folder_name: str, source_tag: str
    ) -> tuple[SafetyLevel, str, str, str]:
        """Classifies a folder from AppData\\Roaming, AppData\\Local, or ~ hidden folders.
        
        Returns:
            (safety_level, safety_badge, description, warning_label)
        """
        lower_name = folder_name.lower().strip()

        # 0. Check Vendor Suite Prefixes (e.g., Adobe, JetBrains, NVIDIA, AMD)
        for prefix, (suite_desc, suite_apps) in self.VENDOR_SUITE_PREFIXES.items():
            if lower_name == prefix or lower_name.startswith(prefix + " ") or lower_name.startswith(prefix + "."):
                suite_installed = any(self._matches_installed(a) is not None for a in suite_apps)
                if suite_installed or self._normalize(prefix) in self.installed_publishers:
                    return (
                        SafetyLevel.INSTALLED_APP,
                        "🔴 Programa en uso (No borrar)",
                        suite_desc,
                        "🔴 COMPONENTE EN USO: Pertenece a un programa o driver instalado en tu PC. No se recomienda borrarlo.",
                    )

        # 1. Check Known Folders Guide
        known_desc: Optional[str] = None
        known_installed: Optional[bool] = None
        if lower_name in self.KNOWN_FOLDERS_GUIDE:
            known_desc, candidate_apps = self.KNOWN_FOLDERS_GUIDE[lower_name]
            known_installed = any(
                self._matches_installed(app_cand) is not None for app_cand in candidate_apps
            )

        # 2. Check exact or prefix match on installed apps
        is_installed = False
        matched_app_label = folder_name

        if known_installed is not None:
            is_installed = known_installed
        else:
            match_title = self._matches_installed(folder_name)
            if match_title is not None:
                is_installed = True
                matched_app_label = match_title
            elif self._normalize(folder_name) in self.installed_publishers:
                is_installed = True

        # 3. Build clear, human-friendly Spanish explanation
        if is_installed:
            desc = (
                known_desc
                or f"Datos activos de «{matched_app_label}» (instalado actualmente en tu PC Windows)."
            )
            warning = (
                "🔴 PROGRAMA INSTALADO: No borres esta carpeta si usas este programa, "
                "para conservar tus datos, perfiles y configuraciones."
            )
            return (
                SafetyLevel.INSTALLED_APP,
                "🔴 Programa en uso (No borrar)",
                desc,
                warning,
            )
        else:
            if known_desc:
                desc = f"{known_desc} (Programa ya desinstalado de tu PC)."
            else:
                desc = (
                    f"No tienes «{folder_name}» instalado en tu PC. "
                    f"Son restos antiguos en {source_tag} de un programa desinstalado."
                )
            warning = (
                "🟢 RESTO HUÉRFANO (SEGURO BORRAR): Este programa ya no está instalado en tu PC. "
                "Puedes enviarlo a la Papelera de reciclaje sin ningún riesgo."
            )
            return (
                SafetyLevel.SAFE,
                "🟢 Programa desinstalado (Seguro borrar)",
                desc,
                warning,
            )

    def inspect_startup_shortcut(self, file_path: str) -> Optional[tuple[SafetyLevel, str, str, str]]:
        """Inspects a file inside the Windows Startup folder (%APPDATA%\\...\\Startup).
        
        Flags orphaned updaters or broken scripts/shortcuts if identifiable.
        """
        fname = os.path.basename(file_path)
        lower_fname = fname.lower()
        if lower_fname == "desktop.ini":
            return None

        stem = os.path.splitext(fname)[0]
        match_title = self._matches_installed(stem)
        if match_title is None:
            return (
                SafetyLevel.REVIEW,
                "🟡 Inicio Automático (Revisar)",
                f"Elemento de arranque automático en Windows («{fname}»). Se ejecuta cada vez que enciendes el PC.",
                "🟡 REVISAR: Si ya no necesitas que este programa arranque al iniciar sesión y consuma RAM, puedes moverlo a la Papelera.",
            )
        return (
            SafetyLevel.REVIEW,
            "🟡 Inicio Automático (Activo)",
            f"Acceso directo de inicio automático de «{match_title}» al arrancar Windows.",
            "🟡 OPCIONAL: Bórralo solo si no quieres que se abra solo al encender el PC (el programa seguirá instalado).",
        )
