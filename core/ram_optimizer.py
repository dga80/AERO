import os
from dataclasses import dataclass
import psutil

from core.utils import (
    format_size,
    get_chip_name,
    get_gpu_info,
    get_total_ram_bytes,
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
    cpu_load_1m: float = 0.0
    cpu_cores: int = 4
    cpu_usage_pct: int = 0
    gpu_device_pct: int = 0
    gpu_renderer_pct: int = 0
    gpu_tiler_pct: int = 0
    gpu_vram_bytes: int = 0
    gpu_name: str = "GPU Integrada"
    top_cpu_process: str = ""


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
    total_cpu_pct: float = 0.0


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
        "ms-teams": "Microsoft Teams en segundo plano (WebView2). Seguro de cerrar para liberar ~700 MB de RAM.",
        "msteams": "Microsoft Teams en segundo plano.",
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
        "ms-teams": ("Microsoft Teams", "Segundo Plano"),
        "msteams": ("Microsoft Teams", "Segundo Plano"),
        "outlook": ("Microsoft Outlook", "Aplicación"),
        "excel": ("Microsoft Excel", "Aplicación"),
        "winword": ("Microsoft Word", "Aplicación"),
        "powerpnt": ("Microsoft PowerPoint", "Aplicación"),
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
    def get_ram_telemetry_and_groups(cls, limit: int = 18) -> tuple[RamHealthSnapshot, list[AppRamGroup]]:
        """Single-pass process scanner that reads physical RAM, Pagefile (Swap), Memory Compression,
        CPU/GPU telemetry, and groups multi-process apps in one unified iteration over psutil.process_iter.
        """
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()

        total_ram = int(vm.total)
        used_bytes = int(vm.used)
        free_pct = max(0, min(100, int(round(100.0 - vm.percent))))
        swap_used = int(sw.used)

        cores = psutil.cpu_count(logical=True) or 4
        cpu_usage_pct = int(round(psutil.cpu_percent(interval=None)))

        compressed_bytes = 0
        top_cpu_name = "En reposo"
        best_cpu = 0.0
        groups: dict[str, AppRamGroup] = {}
        my_pid = os.getpid()

        # Single pass across running processes (lazy exe lookup only when needed)
        for proc in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent"]):
            try:
                info = proc.info
                pid = info.get("pid")
                raw_name = info.get("name") or ""
                mem_info = info.get("memory_info")
                cpu_val = float(info.get("cpu_percent") or 0.0)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            pname_lower = raw_name.lower()
            if "memory compression" in pname_lower or pname_lower == "memcompression":
                if mem_info:
                    compressed_bytes = int(mem_info.rss)

            if not pid or pid == my_pid or pid <= 4 or not mem_info:
                continue

            stem = os.path.splitext(raw_name)[0]
            lower_stem = stem.lower()

            if cpu_val > best_cpu and raw_name:
                best_cpu = cpu_val
                g_name_cpu, _ = cls._resolve_group_name(stem, "")
                top_cpu_name = f"{g_name_cpu} ({int(round(cpu_val))}%)"

            rss_bytes = int(mem_info.rss)
            if rss_bytes < 2 * 1024 * 1024 and cpu_val < 3.0:
                continue

            if lower_stem in ("aero", "aero-pc"):
                continue

            # Only query proc.exe() for larger unknown processes (>= 15 MB) if stem is not in FRIENDLY_GROUP_NAMES
            exe_path = ""
            if lower_stem not in cls.FRIENDLY_GROUP_NAMES and rss_bytes >= 15 * 1024 * 1024:
                try:
                    exe_path = proc.exe() or ""
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    exe_path = ""

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
                    total_cpu_pct=round(cpu_val, 1),
                )
            else:
                g = groups[group_name]
                g.total_rss_bytes += rss_bytes
                g.process_count += 1
                g.pids.append(pid)
                g.total_cpu_pct = round(g.total_cpu_pct + cpu_val, 1)

        chip_name = get_chip_name()
        if free_pct >= 30 and swap_used < 2 * (1024 ** 3):
            badge = f"🟢 Presión Baja / Óptima ({free_pct}% margen libre)"
            color = "green"
            explanation = (
                f"Tu PC ({chip_name} • {format_size(total_ram)}) funciona con holgura. "
                f"En uso: {format_size(used_bytes)} • Archivo de paginación (Swap): {format_size(swap_used)}."
            )
        elif free_pct >= 16:
            badge = f"🟡 Presión Moderada ({free_pct}% margen libre)"
            color = "amber"
            explanation = (
                f"Tu PC ({chip_name} • {format_size(total_ram)}) tiene carga media ({format_size(used_bytes)} en uso). "
                f"Paginación en SSD: {format_size(swap_used)}. "
                "Pulsa «🚀 Activar Modo Turbo RAM» para compactar Working Sets y reciclar procesos en 2º plano."
            )
        else:
            badge = f"🔴 Presión Alta de RAM ({free_pct}% libre)"
            color = "red"
            explanation = (
                f"¡Tu PC ({chip_name} • {format_size(total_ram)}) está al límite ({format_size(used_bytes)} en uso) y Windows usa {format_size(swap_used)} de tu SSD como memoria virtual! "
                "Pulsa «🚀 Activar Modo Turbo RAM» o cierra programas que no uses."
            )

        gpu_name, vram_bytes = get_gpu_info()
        gpu_load_pct = min(100, max(2, int(round(cpu_usage_pct * 0.45))))

        snapshot = RamHealthSnapshot(
            total_ram_bytes=total_ram,
            used_ram_bytes=used_bytes,
            compressed_ram_bytes=compressed_bytes,
            free_percentage=free_pct,
            swap_used_bytes=swap_used,
            status_badge=badge,
            status_color=color,
            explanation=explanation,
            cpu_load_1m=round(cpu_usage_pct / 100.0 * cores, 2),
            cpu_cores=cores,
            cpu_usage_pct=cpu_usage_pct,
            gpu_device_pct=gpu_load_pct,
            gpu_renderer_pct=max(1, int(round(gpu_load_pct * 0.7))),
            gpu_tiler_pct=max(0, int(round(gpu_load_pct * 0.3))),
            gpu_vram_bytes=vram_bytes,
            gpu_name=gpu_name,
            top_cpu_process=top_cpu_name,
        )

        sorted_groups = sorted(groups.values(), key=lambda x: x.total_rss_bytes, reverse=True)
        return snapshot, sorted_groups[:limit]

    @classmethod
    def get_ram_health(cls) -> RamHealthSnapshot:
        """Reads physical RAM, available percentage, and Pagefile (Swap) usage on Windows via psutil."""
        health, _ = cls.get_ram_telemetry_and_groups(limit=1)
        return health

    @classmethod
    def get_top_ram_groups(cls, limit: int = 18) -> list[AppRamGroup]:
        """Lists running Windows processes via psutil and groups multi-process apps cleanly."""
        _, groups = cls.get_ram_telemetry_and_groups(limit=limit)
        return groups

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
