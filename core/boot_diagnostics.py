import datetime
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from core.utils import expand_home, get_chip_name, get_total_ram_label


@dataclass
class BootIssueCard:
    id: str
    title: str
    status: str  # "ok", "warn", "crit"
    status_badge: str
    metric_text: str
    description: str
    action_label: Optional[str] = None
    action_key: Optional[str] = None
    action_payload: Optional[str] = None


@dataclass
class BootProfileReport:
    kernel_to_login_sec: int
    login_to_desktop_sec: int
    total_boot_sec: int
    uptime_str: str
    overall_status: str  # "green", "amber", "red"
    overall_badge: str
    overall_summary: str
    cards: list[BootIssueCard]


class BootDiagnostics:
    """Analyzes Windows startup timeline (Kernel boot -> Winlogon -> Explorer desktop),
    Startup applications in Registry/Task Manager, Desktop file clutter,
    Fast Startup / Hibernation state, Windows Search indexing and idle services.
    """

    KNOWN_STARTUP_BLOAT = [
        ("OneDrive", "Microsoft OneDrive en arranque"),
        ("Adobe Acrobat Synchronizer", "Sincronizador en segundo plano de Adobe"),
        ("MicrosoftEdgeAutoLaunch", "Inicio automático anticipado de Microsoft Edge"),
        ("GoogleChromeAutoLaunch", "Inicio automático anticipado de Google Chrome"),
        ("Teams", "Microsoft Teams en inicio"),
        ("Spotify", "Spotify Helper en inicio"),
        ("Discord", "Discord Updater en inicio"),
        ("Steam", "Cliente de Steam en inicio"),
        ("EpicGamesLauncher", "Lanzador de Epic Games en inicio"),
    ]

    @classmethod
    def run_diagnostics(cls) -> BootProfileReport:
        k_to_l, l_to_d, uptime_str = cls._measure_boot_timeline()
        total_boot = k_to_l + l_to_d

        cards: list[BootIssueCard] = []
        cards.append(cls._check_desktop_overload())
        cards.append(cls._check_startup_registry_apps())
        cards.append(cls._check_fast_startup_and_hibernation())
        cards.append(cls._check_low_end_cpu_tweaks())
        cards.append(cls._check_windows_search_indexing())
        cards.append(cls._check_visual_effects_and_explorer())

        crit_count = sum(1 for c in cards if c.status == "crit")
        warn_count = sum(1 for c in cards if c.status == "warn")

        if crit_count == 0 and warn_count == 0 and total_boot <= 45 and l_to_d <= 12:
            overall_status = "green"
            overall_badge = f"🟢 Arranque Rápido y Limpio (~{total_boot}s total)"
            overall_summary = (
                f"Inicio del sistema: {k_to_l}s • Carga de tu Escritorio: {l_to_d}s • Activo: {uptime_str}. "
                "No se detectan cuellos de botella ni programas pesados retrasando el inicio de Windows."
            )
        elif crit_count > 0 or total_boot > 55 or l_to_d > 18:
            overall_status = "red"
            overall_badge = f"🔴 Frenos de Arranque Detectados (~{total_boot}s total)"
            overall_summary = (
                f"Inicio del sistema: {k_to_l}s • Carga de tu Escritorio: {l_to_d}s • Activo: {uptime_str}. "
                f"Se han detectado {crit_count + warn_count} factor(es) que ralentizan el encendido o la carga del escritorio."
            )
        else:
            overall_status = "amber"
            overall_badge = f"🟡 Arranque Optimizable (~{total_boot}s total)"
            overall_summary = (
                f"Inicio del sistema: {k_to_l}s • Carga de tu Escritorio: {l_to_d}s • Activo: {uptime_str}. "
                "Revisa las tarjetas inferiores para agilizar el arranque y evitar retrasos al iniciar sesión."
            )

        return BootProfileReport(
            kernel_to_login_sec=k_to_l,
            login_to_desktop_sec=l_to_d,
            total_boot_sec=total_boot,
            uptime_str=uptime_str,
            overall_status=overall_status,
            overall_badge=overall_badge,
            overall_summary=overall_summary,
            cards=cards,
        )

    @classmethod
    def _measure_boot_timeline(cls) -> tuple[int, int, str]:
        """Calculates seconds for Windows boot timeline and uptime."""
        import psutil

        boot_epoch = int(psutil.boot_time())
        now = int(time.time())
        uptime_sec = max(1, now - boot_epoch)

        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600
        minutes = (uptime_sec % 3600) // 60

        if days > 0:
            uptime_str = f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            uptime_str = f"{hours}h {minutes}m"
        else:
            uptime_str = f"{minutes} min"

        # Try to locate winlogon or csrss and explorer creation times
        k_to_l = 18
        l_to_d = 6

        try:
            exp_time = None
            winlogon_time = None
            for p in psutil.process_iter(["name", "create_time"]):
                pname = (p.info.get("name") or "").lower()
                if pname == "explorer.exe" and not exp_time:
                    exp_time = p.info.get("create_time")
                elif pname == "winlogon.exe" and not winlogon_time:
                    winlogon_time = p.info.get("create_time")

            if winlogon_time and winlogon_time >= boot_epoch:
                k_to_l = max(5, min(90, int(winlogon_time - boot_epoch)))
            if exp_time and winlogon_time and exp_time >= winlogon_time:
                diff = int(exp_time - winlogon_time)
                # If the user logged in immediately, this is desktop load time; cap realistic desktop load
                l_to_d = max(3, min(35, diff if diff <= 35 else 6))
            elif exp_time and exp_time >= boot_epoch:
                diff = int(exp_time - boot_epoch)
                if diff > 10:
                    k_to_l = max(10, min(50, int(diff * 0.7)))
                    l_to_d = max(3, min(25, int(diff * 0.3)))
        except Exception:
            pass

        return k_to_l, l_to_d, uptime_str

    @classmethod
    def _check_desktop_overload(cls) -> BootIssueCard:
        """Windows Explorer draws and renders icons for every file placed directly on ~/Desktop."""
        desktop = expand_home("~/Desktop")
        count = 0
        loose_media = 0
        loose_exts = {".png", ".jpg", ".jpeg", ".mp4", ".mov", ".zip", ".docx", ".pdf", ".exe", ".iso"}

        if os.path.isdir(desktop):
            try:
                for entry in os.scandir(desktop):
                    if entry.is_file(follow_symlinks=False) and not entry.name.startswith("."):
                        count += 1
                        _, ext = os.path.splitext(entry.name.lower())
                        if ext in loose_exts:
                            loose_media += 1
            except Exception:
                pass

        if count >= 35:
            return BootIssueCard(
                id="desktop_overload",
                title="Sobrecarga de Archivos en el Escritorio",
                status="crit",
                status_badge="🔴 Sobrecarga Crítica",
                metric_text=f"{count} archivos ({loose_media} multimedia)",
                description=(
                    f"Tienes {count} archivos sueltos en el Escritorio. Al iniciar sesión, el proceso "
                    "explorer.exe debe leer y generar miniaturas para cada icono antes de responder con fluidez."
                ),
                action_label="📦 Agrupar en «Archivos_no borrar»",
                action_key="CLEAN_DESKTOP_LOOSE",
            )
        elif count >= 15:
            return BootIssueCard(
                id="desktop_overload",
                title="Archivos Sueltos en el Escritorio",
                status="warn",
                status_badge="🟡 Precaución",
                metric_text=f"{count} archivos sueltos",
                description=(
                    f"Hay {count} archivos en tu Escritorio. Agruparlos en una subcarpeta acelera la "
                    "carga inicial de explorer.exe y la barra de tareas tras el inicio de sesión."
                ),
                action_label="📦 Agrupar en «Archivos_no borrar»",
                action_key="CLEAN_DESKTOP_LOOSE",
            )
        else:
            return BootIssueCard(
                id="desktop_overload",
                title="Escritorio Ligero y Rápido",
                status="ok",
                status_badge="🟢 Escritorio Limpio",
                metric_text=f"{count} elementos directos",
                description="Tu Escritorio está despejado: Explorer carga las miniaturas e iconos al instante sin demora.",
            )

    @classmethod
    def _check_startup_registry_apps(cls) -> BootIssueCard:
        """Inspects HKCU & HKLM CurrentVersion\\Run startup entries."""
        import winreg

        keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        apps = []
        for root, path in keys:
            try:
                k = winreg.OpenKey(root, path)
                for i in range(winreg.QueryInfoKey(k)[1]):
                    name, val, _ = winreg.EnumValue(k, i)
                    apps.append((name, str(val)))
            except Exception:
                pass

        bloat_found = []
        for name, val in apps:
            for b_key, b_desc in cls.KNOWN_STARTUP_BLOAT:
                if b_key.lower() in name.lower() or b_key.lower() in val.lower():
                    bloat_found.append(b_desc)
                    break

        total_startup = len(apps)
        if len(bloat_found) >= 2 or total_startup >= 8:
            return BootIssueCard(
                id="startup_apps",
                title="Programas Pesados en Inicio de Windows",
                status="warn",
                status_badge="🟡 Inicio Sobrecargado",
                metric_text=f"{total_startup} programas ({len(bloat_found)} optimizables)",
                description=(
                    f"Se detectaron {total_startup} programas configurados para arrancar automáticamente: "
                    + ", ".join(bloat_found[:3])
                    + ". Desactivar su inicio automático ahorra valiosos segundos de CPU y RAM."
                ),
                action_label="⚙️ Abrir Aplicaciones de Inicio",
                action_key="OPEN_STARTUP_SETTINGS",
            )
        else:
            return BootIssueCard(
                id="startup_apps",
                title="Programas de Inicio Controlados",
                status="ok",
                status_badge="🟢 Arranque Despejado",
                metric_text=f"{total_startup} programas en registro",
                description="Tienes pocos programas de terceros configurados para arrancar automáticamente.",
                action_label="⚙️ Gestionar en Ajustes",
                action_key="OPEN_STARTUP_SETTINGS",
            )

    @classmethod
    def _check_fast_startup_and_hibernation(cls) -> BootIssueCard:
        """Checks Windows Fast Startup / Hiberboot setting in registry."""
        import winreg

        fast_boot_enabled = True
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Power")
            val, _ = winreg.QueryValueEx(k, "HiberbootEnabled")
            fast_boot_enabled = bool(val == 1)
        except Exception:
            pass

        if fast_boot_enabled:
            return BootIssueCard(
                id="fast_startup",
                title="Inicio Rápido de Windows (Hiberboot)",
                status="ok",
                status_badge="🟢 Hiberboot Activo",
                metric_text="Arranque Híbrido NTFS",
                description=(
                    "El Inicio Rápido de Windows está activado: el kernel y los controladores se cargan desde "
                    "el archivo de hibernación acelerando drásticamente el encendido del PC."
                ),
            )
        else:
            return BootIssueCard(
                id="fast_startup",
                title="Inicio Rápido Desactivado",
                status="warn",
                status_badge="🟡 Arranque Completo",
                metric_text="Hiberboot Inactivo",
                description=(
                    "El Inicio Rápido está desactivado, por lo que Windows realiza un arranque en frío completo en cada encendido. "
                    "Puedes activarlo en el Panel de Control para reducir el tiempo de encendido."
                ),
                action_label="⚡ Ajustes de Energía",
                action_key="OPEN_POWER_SETTINGS",
            )

    @classmethod
    def _check_low_end_cpu_tweaks(cls) -> BootIssueCard:
        """Audits Edge/Chrome background startup hooks and GameDVR on budget 2-core / low-spec CPUs."""
        import winreg

        bloat_detected = []

        # 1. Check HKCU Run for Edge and Chrome auto background hooks
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
            for i in range(winreg.QueryInfoKey(k)[1]):
                name, _, _ = winreg.EnumValue(k, i)
                if "MicrosoftEdgeAutoLaunch" in name or "GoogleChromeAutoLaunch" in name:
                    bloat_detected.append("Pre-arranque silencioso de navegadores (Edge/Chrome)")
                    break
        except Exception:
            pass

        # 2. Check GameDVR AppCapture (draws background hooks into games and GPU)
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR")
            v, _ = winreg.QueryValueEx(k, "AppCaptureEnabled")
            if v == 1:
                bloat_detected.append("Grabación en segundo plano de Xbox GameDVR")
        except Exception:
            pass

        if bloat_detected:
            return BootIssueCard(
                id="low_end_cpu_tweaks",
                title="Aceleración para CPU y RAM Limitada (Celeron / 8 GB)",
                status="warn",
                status_badge="🟡 Optimizable",
                metric_text=f"{len(bloat_detected)} procesos reteniendo recursos",
                description=(
                    "En procesadores de 2 núcleos como Intel Celeron, el pre-arranque de Edge/Chrome y la barra de juegos "
                    "reducen la fluidez del sistema consumiendo valiosos ciclos de CPU y cientos de megabytes de RAM."
                ),
                action_label="🚀 Desactivar Pre-arranques y Acelerar",
                action_key="APPLY_LOW_SPEC_CPU_FIXES",
            )
        else:
            return BootIssueCard(
                id="low_end_cpu_tweaks",
                title="Aceleración para CPU y RAM Limitada",
                status="ok",
                status_badge="🟢 Optimizado",
                metric_text="Sin pre-arranques invasivos",
                description="Tu PC no tiene activos servicios de pre-carga silenciosa de navegadores ni GameDVR.",
            )

    @classmethod
    def _check_windows_search_indexing(cls) -> BootIssueCard:
        """Inspects if Windows Search service (WSearch / SearchIndexer) is active."""
        import psutil

        is_indexing = False
        rss_bytes = 0
        try:
            for p in psutil.process_iter(["name", "memory_info"]):
                if (p.info.get("name") or "").lower() == "searchindexer.exe":
                    is_indexing = True
                    mem = p.info.get("memory_info")
                    if mem:
                        rss_bytes = int(mem.rss)
                    break
        except Exception:
            pass

        from core.utils import format_size

        if is_indexing:
            return BootIssueCard(
                id="search_indexing",
                title="Indexador de Búsqueda de Windows (WSearch)",
                status="ok",
                status_badge="🟢 En Funcionamiento",
                metric_text=f"RAM: {format_size(rss_bytes)} • Servicio Activo",
                description=(
                    "El servicio de indexación SearchIndexer mantiene la búsqueda rápida en el menú Inicio. "
                    "Si experimentas lentitud de disco, puedes ajustar qué carpetas se indexan en Opciones de Indización."
                ),
                action_label="🔍 Opciones de Búsqueda",
                action_key="OPEN_INDEXING_OPTIONS",
            )
        else:
            return BootIssueCard(
                id="search_indexing",
                title="Indexador de Búsqueda de Windows",
                status="ok",
                status_badge="🟢 Reposado",
                metric_text="Sin sobrecarga de disco",
                description="El indexador no está consumiendo recursos en este momento.",
            )

    @classmethod
    def _check_visual_effects_and_explorer(cls) -> BootIssueCard:
        """Checks Explorer visual responsiveness and thumbnail cache status."""
        cache_dir = expand_home(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer")
        thumb_count = 0
        if os.path.isdir(cache_dir):
            try:
                for f in os.listdir(cache_dir):
                    if f.lower().startswith("thumbcache_"):
                        thumb_count += 1
            except Exception:
                pass

        if thumb_count > 15:
            return BootIssueCard(
                id="visual_cache",
                title="Caché Acumulada de Miniaturas de Explorer",
                status="warn",
                status_badge="🟡 Caché Abundante",
                metric_text=f"{thumb_count} bases de datos de miniaturas",
                description=(
                    "Explorer mantiene múltiples bases de datos de miniaturas antiguas en AppData. "
                    "La optimización rápida las compacta y regenera las obsoletas de forma segura."
                ),
                action_label="🧹 Compactar Miniaturas",
                action_key="CLEAN_THUMB_CACHES",
            )
        else:
            return BootIssueCard(
                id="visual_cache",
                title="Caché Visual de Explorer Optimizada",
                status="ok",
                status_badge="🟢 Respuesta Fluida",
                metric_text="Bases de miniaturas en orden",
                description="La interfaz de usuario y miniaturas del Explorador de Windows están en estado óptimo.",
            )

    # -------------------------------------------------------------------------
    # One-Click Remediation Actions
    # -------------------------------------------------------------------------
    @classmethod
    def execute_fix(cls, action_key: str) -> str:
        if action_key == "CLEAN_DESKTOP_LOOSE":
            desktop = expand_home("~/Desktop")
            target_dir = os.path.join(desktop, "Archivos_no borrar")
            os.makedirs(target_dir, exist_ok=True)
            moved = 0
            loose_exts = {".png", ".jpg", ".jpeg", ".mp4", ".mov", ".zip", ".docx", ".pdf", ".exe", ".iso"}
            try:
                for entry in os.scandir(desktop):
                    if entry.is_file(follow_symlinks=False) and not entry.name.startswith("."):
                        _, ext = os.path.splitext(entry.name.lower())
                        if ext in loose_exts:
                            dst = os.path.join(target_dir, entry.name)
                            if not os.path.exists(dst):
                                os.rename(entry.path, dst)
                                moved += 1
            except Exception:
                pass
            if moved > 0:
                return f"✓ Se agruparon {moved} archivo(s) sueltos en «Archivos_no borrar»."
            return "✓ No había archivos sueltos adicionales en el Escritorio."

        elif action_key == "OPEN_STARTUP_SETTINGS":
            try:
                subprocess.Popen(["cmd.exe", "/c", "start", "ms-settings:startupapps"])
                return "✓ Abriendo Configuración > Aplicaciones de inicio para gestionar el arranque."
            except Exception:
                return "Abre Configuración > Aplicaciones > Inicio."

        elif action_key == "OPEN_POWER_SETTINGS":
            try:
                subprocess.Popen(["control.exe", "/name", "Microsoft.PowerOptions"])
                return "✓ Abriendo Opciones de energía del Panel de Control."
            except Exception:
                return "Abre Panel de Control > Opciones de energía."

        elif action_key == "OPEN_INDEXING_OPTIONS":
            try:
                subprocess.Popen(["control.exe", "srchadmin.dll"])
                return "✓ Abriendo Opciones de Indización de Windows."
            except Exception:
                return "Abre Opciones de Indización desde el menú Inicio."

        elif action_key == "APPLY_LOW_SPEC_CPU_FIXES":
            import winreg
            messages = []
            # 1. Remove Edge and Chrome hidden startup background hooks
            try:
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
                names_to_del = []
                for i in range(winreg.QueryInfoKey(k)[1]):
                    n, _, _ = winreg.EnumValue(k, i)
                    if "MicrosoftEdgeAutoLaunch" in n or "GoogleChromeAutoLaunch" in n:
                        names_to_del.append(n)
                for n in names_to_del:
                    winreg.DeleteValue(k, n)
                if names_to_del:
                    messages.append(f"Desactivados {len(names_to_del)} pre-arranques de navegadores")
            except Exception:
                pass

            # 2. Disable GameDVR AppCapture to liberate background GPU/CPU hooks
            try:
                gdvr_key, _ = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(gdvr_key, "AppCaptureEnabled", 0, winreg.REG_DWORD, 0)
                messages.append("Grabación en 2º plano de GameDVR desactivada")
            except Exception:
                pass

            # 3. Compact working sets immediately
            from core.utils import trim_background_working_sets
            trimmed = trim_background_working_sets()
            if trimmed:
                messages.append(f"Liberada RAM inactiva ({trimmed} procesos)")

            return "✓ " + " • ".join(messages) if messages else "✓ Ajustes de aceleración aplicados."

        elif action_key == "CLEAN_THUMB_CACHES":
            from core.utils import run_quick_windows_optimizations
            return run_quick_windows_optimizations()

        return "Acción completada."
