import os
from dataclasses import dataclass
import psutil

from core.utils import (
    format_size,
    run_quick_windows_optimizations,
    trim_background_working_sets,
)


@dataclass
class RamHealthSnapshot:
    total_ram_bytes: int
    used_ram_bytes: int
    compressed_ram_bytes: int
    free_percentage: int
    swap_used_bytes: int
    status_badge: str
    status_color: str  # "green", "amber", "red"
    explanation: str


@dataclass
class AppRamGroup:
    app_name: str
    category: str
    total_rss_bytes: int
    process_count: int
    pids: list[int]
    is_recyclable_daemon: bool
    is_protected: bool
    description: str


class RamOptimizer:
    """Monitors Windows Physical RAM (8 GB / 16 GB+), Pagefile (Swap) usage, and groups multi-process apps
    so non-technical users can see what is eating their RAM and safely free background bloatware/daemons
    plus compact Windows Working Sets (`EmptyWorkingSet`).
    """

    # Background services/bloatware on Windows 10/11 that frequently bloat in RAM and are 100% safe
    # to terminate (Windows restarts them on demand only if opened).
    RECYCLABLE_DAEMONS: dict[str, str] = {
        "widgets": "Panel de Widgets y Noticias de Windows 11 (WebView2). Consume mucha RAM en segundo plano; 100% seguro reciclarlo.",
        "widgetservice": "Servicio de Widgets de Windows 11 en segundo plano. 100% seguro de liberar.",
        "searchhost": "Interfaz de búsqueda indexada del menú Inicio de Windows. Se suspende/reinicia al instante liberando RAM.",
        "textinputhost": "Proceso en caché del panel de emojis y entrada táctil de Windows. Seguro de reciclar.",
        "phoneexperiencehost": "Enlace Móvil (Tu Teléfono) de Windows corriendo en segundo plano. Seguro de liberar.",
        "gamebar": "Superposición de Xbox Game Bar en segundo plano. Seguro de liberar si no estás grabando partida.",
        "gamebarftserver": "Servidor en segundo plano de Xbox Game Bar. 100% seguro de liberar.",
        "xboxpcappft": "Proceso auxiliar de la app Xbox en segundo plano. Seguro de liberar.",
        "microsoft.photos": "Visor de Fotos de Windows mantenido en memoria en segundo plano. Seguro de liberar.",
        "calculatorapp": "Calculadora de Windows en segundo plano. Seguro de liberar.",
        "video.ui": "Reproductor Películas y TV en segundo plano. Seguro de liberar.",
        "yourphone": "Proceso en segundo plano de Enlace Móvil. Seguro de liberar.",
        "LockApp": "Pantalla de bloqueo en caché de Windows. Seguro de reciclar.",
        "microsoftedgeupdate": "Actualizador silencioso de Microsoft Edge en segundo plano.",
        "googleupdate": "Actualizador silencioso de Google Chrome en segundo plano.",
        "braveupdate": "Actualizador en segundo plano de Brave Browser.",
        "onedrivestandaloneupdater": "Actualizador en segundo plano de Microsoft OneDrive.",
        "cortana": "Asistente Cortana en segundo plano. 100% seguro de liberar.",
        "skypeapp": "Proceso residual de Skype en segundo plano.",
        "teams": "Cliente de Microsoft Teams en segundo plano.",
        "msteamsupdate": "Actualizador de Microsoft Teams en segundo plano.",
        "coresync": "Demonio de sincronización en segundo plano de Adobe Creative Cloud.",
        "ccxprocess": "Proceso en segundo plano de Adobe Creative Cloud.",
        "adobeipcbroker": "Proceso intercomunicador de Adobe en segundo plano.",
        "adobecollabsync": "Sincronizador en segundo plano de Adobe Acrobat.",
        "acrotray": "Asistente en bandeja de Adobe Acrobat.",
        "armsvc": "Agente de actualización de Adobe Acrobat.",
        "steamwebhelper": "Navegador interno en segundo plano de Steam.",
    }

    # Core Windows OS & current session processes that should NEVER be killed by the user
    PROTECTED_APPS = {
        "aero",
        "antigravity",
        "python",
        "pythonw",
        "system",
        "registry",
        "smss",
        "csrss",
        "wininit",
        "services",
        "lsass",
        "svchost",
        "winlogon",
        "explorer",
        "dwm",
        "fontdrvhost",
        "sihost",
        "taskhostw",
        "ctfmon",
        "runtimebroker",
        "applicationframehost",
        "startmenuexperiencehost",
        "shellexperiencehost",
        "audiodg",
        "spoolsv",
        "msmpeng",
        "nissrv",
        "securityhealthservice",
        "securityhealthsystray",
        "conhost",
        "powershell",
        "pwsh",
        "cmd",
        "WmiPrvSE",
        "dllhost",
        "searchindexer",
        "memory compression",
    }

    FRIENDLY_GROUP_NAMES: dict[str, tuple[str, str]] = {
        "chrome": ("Google Chrome", "Aplicación"),
        "msedge": ("Microsoft Edge", "Aplicación"),
        "msedgewebview2": ("Microsoft WebView2 (Widgets / Apps)", "Segundo Plano"),
        "firefox": ("Mozilla Firefox", "Aplicación"),
        "brave": ("Brave Browser", "Aplicación"),
        "opera": ("Opera Browser", "Aplicación"),
        "antigravity": ("Antigravity IDE", "Aplicación"),
        "code": ("Visual Studio Code", "Aplicación"),
        "cursor": ("Cursor IDE", "Aplicación"),
        "devenv": ("Microsoft Visual Studio", "Aplicación"),
        "pycharm64": ("JetBrains PyCharm", "Aplicación"),
        "idea64": ("JetBrains IntelliJ IDEA", "Aplicación"),
        "studio64": ("Android Studio", "Aplicación"),
        "explorer": ("Explorador de Windows (Escritorio)", "Sistema Windows"),
        "dwm": ("Gestor de Ventanas de Escritorio (DWM)", "Sistema Windows"),
        "msmpeng": ("Windows Defender Antivirus", "Sistema Windows"),
        "svchost": ("Servicios del Sistema Windows (svchost)", "Sistema Windows"),
        "memory compression": ("Compresión de Memoria de Windows", "Sistema Windows"),
        "searchhost": ("SearchHost (Búsqueda de Windows)", "Segundo Plano"),
        "widgets": ("Widgets y Noticias de Windows", "Segundo Plano"),
        "widgetservice": ("Widgets y Noticias de Windows", "Segundo Plano"),
        "phoneexperiencehost": ("Enlace Móvil (Phone Link)", "Segundo Plano"),
        "discord": ("Discord", "Aplicación"),
        "spotify": ("Spotify", "Aplicación"),
        "slack": ("Slack", "Aplicación"),
        "telegram": ("Telegram Desktop", "Aplicación"),
        "whatsapp": ("WhatsApp Desktop", "Aplicación"),
        "steam": ("Steam", "Aplicación"),
        "steamwebhelper": ("Steam", "Aplicación"),
        "nvcontainer": ("NVIDIA Container (Drivers)", "Servicio Hardware"),
        "nvidia share": ("NVIDIA Overlay", "Servicio Hardware"),
        "radeonsoftware": ("AMD Radeon Software", "Servicio Hardware"),
        "onedrive": ("Microsoft OneDrive", "Segundo Plano"),
    }

    APP_DESCRIPTIONS: dict[str, str] = {
        "Google Chrome": "Navegador web (suma la ventana principal, extensiones y todas las pestañas abiertas).",
        "Microsoft Edge": "Navegador web de Microsoft (suma todas las pestañas y procesos en segundo plano).",
        "Microsoft WebView2 (Widgets / Apps)": "Motor web embebido usado por Widgets de Windows y apps modernas.",
        "Antigravity IDE": "Tu entorno de desarrollo e IA actual (protegido para no cerrar tu sesión activa).",
        "Visual Studio Code": "Editor de código y todos sus servidores de lenguaje / extensiones activas.",
        "Explorador de Windows (Escritorio)": "Gestor de archivos, barra de tareas y escritorio de tu PC Windows.",
        "Gestor de Ventanas de Escritorio (DWM)": "Motor gráfico de Windows que dibuja las ventanas y efectos visuales.",
        "Windows Defender Antivirus": "Motor de seguridad en tiempo real de Windows (Antimalware Service Executable).",
        "Servicios del Sistema Windows (svchost)": "Conjunto de servicios internos esenciales del sistema operativo Windows.",
        "Compresión de Memoria de Windows": "Bloque de RAM comprimida por el kernel de Windows para evitar usar el disco SSD.",
        "SearchHost (Búsqueda de Windows)": "Interfaz de búsqueda del menú Inicio; se puede reciclar sin riesgo para recuperar RAM.",
        "Widgets y Noticias de Windows": "Panel de noticias y clima de la barra de tareas; consume bastante RAM y es 100% seguro reciclarlo.",
        "Enlace Móvil (Phone Link)": "Sincronización con el móvil en segundo plano; seguro de liberar si no lo usas.",
    }

    @classmethod
    def get_ram_health(cls) -> RamHealthSnapshot:
        """Reads physical RAM, available percentage, and Pagefile (Swap) usage on Windows via psutil."""
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()

        total_ram = int(vm.total)
        used_bytes = int(vm.used)
        free_pct = max(0, min(100, int(round(100.0 - vm.percent))))
        swap_used = int(sw.used)

        # Estimate Memory Compression process RSS if available on Windows
        compressed_bytes = 0
        try:
            for p in psutil.process_iter(["name", "memory_info"]):
                pname = (p.info.get("name") or "").lower()
                if "memory compression" in pname or pname == "memcompression":
                    mem_info = p.info.get("memory_info")
                    if mem_info:
                        compressed_bytes = int(mem_info.rss)
                    break
        except Exception:
            pass

        if free_pct >= 30 and swap_used < 2 * (1024 ** 3):
            badge = f"🟢 Presión Baja / Óptima ({free_pct}% margen libre)"
            color = "green"
            explanation = (
                f"Tu PC de {format_size(total_ram)} de RAM funciona con holgura. "
                f"En uso: {format_size(used_bytes)} • Archivo de paginación (Swap): {format_size(swap_used)}."
            )
        elif free_pct >= 16:
            badge = f"🟡 Presión Moderada ({free_pct}% margen libre)"
            color = "amber"
            explanation = (
                f"Tu RAM de {format_size(total_ram)} tiene carga media ({format_size(used_bytes)} en uso). "
                f"Paginación en SSD: {format_size(swap_used)}. "
                "Pulsa «🚀 Activar Modo Turbo RAM» para compactar Working Sets y reciclar procesos en 2º plano."
            )
        else:
            badge = f"🔴 Presión Alta de RAM ({free_pct}% libre)"
            color = "red"
            explanation = (
                f"¡Tus {format_size(total_ram)} están al límite ({format_size(used_bytes)} en uso) y Windows usa {format_size(swap_used)} de tu SSD como memoria virtual! "
                "Pulsa «🚀 Activar Modo Turbo RAM» o cierra programas que no uses."
            )

        return RamHealthSnapshot(
            total_ram_bytes=total_ram,
            used_ram_bytes=used_bytes,
            compressed_ram_bytes=compressed_bytes,
            free_percentage=free_pct,
            swap_used_bytes=swap_used,
            status_badge=badge,
            status_color=color,
            explanation=explanation,
        )

    @classmethod
    def get_top_ram_groups(cls, limit: int = 18) -> list[AppRamGroup]:
        """Lists running Windows processes via psutil and groups multi-process apps cleanly."""
        groups: dict[str, AppRamGroup] = {}
        my_pid = os.getpid()

        for proc in psutil.process_iter(["pid", "name", "memory_info", "exe"]):
            try:
                pid = proc.info.get("pid")
                raw_name = proc.info.get("name") or ""
                mem_info = proc.info.get("memory_info")
                exe_path = proc.info.get("exe") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            if not pid or pid == my_pid or pid <= 4 or not mem_info:
                continue

            rss_bytes = int(mem_info.rss)
            if rss_bytes < 2 * 1024 * 1024:  # Ignore tiny processes < 2 MB
                continue

            stem = os.path.splitext(raw_name)[0]
            lower_stem = stem.lower()

            if lower_stem in ("aero", "aero-pc"):
                continue

            group_name, category = cls._resolve_group_name(stem, exe_path)
            lower_group = group_name.lower()

            is_protected = (
                lower_stem in cls.PROTECTED_APPS
                or any(p == lower_group for p in cls.PROTECTED_APPS)
                or "antigravity" in lower_group
            )
            is_recyclable = (
                not is_protected
                and (
                    lower_stem in cls.RECYCLABLE_DAEMONS
                    or any(k in lower_stem for k in cls.RECYCLABLE_DAEMONS)
                )
            )

            if group_name not in groups:
                desc = cls._get_description(group_name, lower_stem, exe_path, is_recyclable)
                groups[group_name] = AppRamGroup(
                    app_name=group_name,
                    category=category,
                    total_rss_bytes=rss_bytes,
                    process_count=1,
                    pids=[pid],
                    is_recyclable_daemon=is_recyclable,
                    is_protected=is_protected,
                    description=desc,
                )
            else:
                g = groups[group_name]
                g.total_rss_bytes += rss_bytes
                g.process_count += 1
                g.pids.append(pid)

        sorted_groups = sorted(groups.values(), key=lambda x: x.total_rss_bytes, reverse=True)
        return sorted_groups[:limit]

    @classmethod
    def _resolve_group_name(cls, stem: str, exe_path: str) -> tuple[str, str]:
        lower_stem = stem.lower()
        if lower_stem in cls.FRIENDLY_GROUP_NAMES:
            return cls.FRIENDLY_GROUP_NAMES[lower_stem]

        lower_exe = exe_path.lower()
        if "antigravity" in lower_exe:
            return ("Antigravity IDE", "Aplicación")
        if "\\microsoft vs code\\" in lower_exe:
            return ("Visual Studio Code", "Aplicación")
        if "\\google\\chrome\\" in lower_exe:
            return ("Google Chrome", "Aplicación")
        if "\\microsoft\\edge\\" in lower_exe and "webview" not in lower_exe:
            return ("Microsoft Edge", "Aplicación")
        if "\\windowsapps\\" in lower_exe or "\\systemapps\\" in lower_exe:
            return (stem, "App Windows")
        if "\\windows\\system32" in lower_exe or "\\windows\\syswow64" in lower_exe:
            return (stem, "Sistema Windows")

        return (stem, "Aplicación / Proceso")

    @classmethod
    def _get_description(cls, group_name: str, lower_stem: str, exe_path: str, is_recyclable: bool) -> str:
        if group_name in cls.APP_DESCRIPTIONS:
            return cls.APP_DESCRIPTIONS[group_name]
        for key, desc in cls.RECYCLABLE_DAEMONS.items():
            if key == lower_stem or key in lower_stem:
                return desc
        if is_recyclable:
            return "Proceso en segundo plano de Windows que puede reciclarse de forma segura para liberar RAM."
        if "\\windows\\" in exe_path.lower():
            return "Componente o servicio interno del sistema operativo Windows."
        return f"Memoria física (Working Set) utilizada por «{group_name}» y sus subprocesos."

    @classmethod
    def free_process_group(cls, group: AppRamGroup) -> tuple[bool, int, str]:
        """Safely terminates a recyclable background process or user app, and trims working sets."""
        if group.is_protected:
            return False, 0, f"«{group.app_name}» está protegido para no interrumpir Windows ni tu sesión."

        freed_estimate = group.total_rss_bytes
        killed_any = False

        for pid in group.pids:
            try:
                p = psutil.Process(pid)
                p.terminate()
                killed_any = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue

        if killed_any:
            return True, freed_estimate, f"✓ Se liberaron ~{format_size(freed_estimate)} de RAM de «{group.app_name}»."
        return False, 0, f"No fue posible detener «{group.app_name}» (proceso protegido por el Administrador de Windows)."

    @classmethod
    def run_turbo_ram_boost(cls) -> tuple[int, int, str]:
        """1. Terminates safe recyclable background bloatware (Widgets, SearchHost, Updaters, GameBar, etc.).
        2. Calls Windows API `EmptyWorkingSet` across all accessible background processes to reclaim idle RAM pages.
        3. Flushes DNS cache and cleans unlocked Explorer thumbnail caches.
        """
        before_vm = psutil.virtual_memory()
        groups = cls.get_top_ram_groups(limit=60)
        count_recycled = 0
        daemon_freed = 0

        for g in groups:
            if g.is_recyclable_daemon and not g.is_protected:
                ok, freed, _ = cls.free_process_group(g)
                if ok:
                    daemon_freed += freed
                    count_recycled += 1

        # Trim idle RAM working sets across processes using Windows Kernel32/Psapi EmptyWorkingSet
        trimmed_procs = trim_background_working_sets()
        run_quick_windows_optimizations()

        after_vm = psutil.virtual_memory()
        actual_delta = max(0, int(after_vm.available) - int(before_vm.available))
        total_reclaimed = max(actual_delta, daemon_freed)

        if total_reclaimed > 0 or trimmed_procs > 0:
            msg = (
                f"🚀 Modo Turbo RAM completado: ~{format_size(total_reclaimed)} de RAM recuperados "
                f"({count_recycled} proceso(s) reciclados, {trimmed_procs} Working Sets compactados + DNS limpio)."
            )
        else:
            msg = (
                "🚀 Modo Turbo RAM completado: Tu memoria RAM y caché DNS ya están optimizadas al máximo."
            )
        return count_recycled, total_reclaimed, msg
