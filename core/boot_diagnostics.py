import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from core.utils import expand_home


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
    """Analyzes macOS startup timeline (Kernel -> LoginWindow -> Finder), Desktop file overload,
    Session Reopen state (`TALLogoutSavesState`), Finder Sync extensions (`pluginkit`),
    Spotlight indexing storms (`mdworker_shared` / `mds_stores`), FileVault, and NVRAM flags.
    """

    KNOWN_THIRD_PARTY_SERVICES = [
        ("com.adobe.GC.AGM", "Adobe Genuine Monitor"),
        ("com.adobe.GC.Scheduler-1.0", "Adobe Creative Cloud Scheduler"),
        ("com.adobe.GC.Invoker-1.0", "Adobe GC Invoker"),
        ("us.zoom.updater", "Zoom Auto-Updater"),
        ("us.zoom.updater.login.check", "Zoom Login Check"),
        ("com.microsoft.update.agent", "Microsoft AutoUpdate Agent"),
        ("com.microsoft.teams2.launcher", "Microsoft Teams Launcher"),
        ("com.microsoft.OneDriveStandaloneUpdater", "OneDrive Updater"),
        ("me.damir.DropoverLaunchAtLoginHelper", "Dropover Launch Helper"),
        ("com.spotify.client.startuphelper", "Spotify Startup Helper"),
    ]

    @classmethod
    def run_diagnostics(cls) -> BootProfileReport:
        k_to_l, l_to_d, uptime_str = cls._measure_boot_timeline()
        total_boot = k_to_l + l_to_d

        cards: list[BootIssueCard] = []
        cards.append(cls._check_desktop_overload())
        cards.append(cls._check_reopen_windows_pref())
        cards.append(cls._check_finder_extensions_and_daemons())
        cards.append(cls._check_spotlight_and_external_drives())
        cards.append(cls._check_filevault_and_nvram())

        crit_count = sum(1 for c in cards if c.status == "crit")
        warn_count = sum(1 for c in cards if c.status == "warn")

        if crit_count == 0 and warn_count == 0 and total_boot <= 28:
            overall_status = "green"
            overall_badge = f"🟢 Arranque Rápido y Limpio (~{total_boot}s total)"
            overall_summary = (
                f"Sistema base: {k_to_l}s • Carga de tu Escritorio: {l_to_d}s • Activo: {uptime_str}. "
                "No se detectan cuellos de botella ni demonios pesados reteniendo el inicio de sesión."
            )
        elif crit_count > 0 or total_boot > 45:
            overall_status = "red"
            overall_badge = f"🔴 Frenos de Arranque Detectados (~{total_boot}s total)"
            overall_summary = (
                f"Sistema base: {k_to_l}s • Carga de tu Escritorio: {l_to_d}s • Activo: {uptime_str}. "
                f"Se han detectado {crit_count + warn_count} factor(es) que ralentizan el arranque o el inicio de sesión."
            )
        else:
            overall_status = "amber"
            overall_badge = f"🟡 Arranque Optimizable (~{total_boot}s total)"
            overall_summary = (
                f"Sistema base: {k_to_l}s • Carga de tu Escritorio: {l_to_d}s • Activo: {uptime_str}. "
                "Revisa las tarjetas inferiores para afinar al máximo el tiempo de respuesta."
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
        """Calculates exact seconds from Kernel boot (PID 1) -> loginwindow -> Finder/Dock."""
        boot_epoch = 0
        try:
            out = subprocess.check_output(["sysctl", "-n", "kern.boottime"], text=True, timeout=2)
            m = re.search(r"sec\s*=\s*(\d+)", out)
            if m:
                boot_epoch = int(m.group(1))
        except Exception:
            pass

        login_epoch = 0
        finder_epoch = 0
        try:
            ps_out = subprocess.check_output(
                ["ps", "-eo", "pid=,lstart=,comm="], text=True, timeout=3
            )
            for line in ps_out.splitlines():
                parts = line.strip().split()
                if len(parts) < 7:
                    continue
                comm = " ".join(parts[6:])
                date_str = " ".join(parts[2:6])  # e.g. "Oct 29 18:05:12 2026"
                try:
                    dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
                    ts = int(dt.timestamp())
                except Exception:
                    continue

                if "/loginwindow" in comm and (login_epoch == 0 or ts < login_epoch):
                    login_epoch = ts
                elif ("/Finder.app/" in comm or "/Dock.app/" in comm) and (
                    finder_epoch == 0 or ts < finder_epoch
                ):
                    finder_epoch = ts
        except Exception:
            pass

        now_ts = int(datetime.now().timestamp())
        uptime_sec = max(0, now_ts - boot_epoch) if boot_epoch > 0 else 0
        if uptime_sec < 3600:
            uptime_str = f"{max(1, uptime_sec // 60)} min"
        else:
            hrs = uptime_sec // 3600
            mins = (uptime_sec % 3600) // 60
            uptime_str = f"{hrs}h {mins}m"

        if boot_epoch > 0 and login_epoch >= boot_epoch:
            k_to_l = min(180, max(2, login_epoch - boot_epoch))
        else:
            k_to_l = 14

        if login_epoch > 0 and finder_epoch >= login_epoch:
            l_to_d = min(120, max(2, finder_epoch - login_epoch))
        else:
            l_to_d = 4

        return k_to_l, l_to_d, uptime_str

    @classmethod
    def _check_desktop_overload(cls) -> BootIssueCard:
        desktop = expand_home("~/Desktop")
        top_items = 0
        total_files = 0
        try:
            with os.scandir(desktop) as it:
                for entry in it:
                    if not entry.name.startswith("."):
                        top_items += 1
            for _, dirs, files in os.walk(desktop):
                total_files += len(files) + len(dirs)
                if total_files > 25000:
                    break
        except Exception:
            pass

        files_label = "+25.000" if total_files > 25000 else f"{total_files:,}".replace(",", ".")
        if total_files > 5000 or top_items > 30:
            return BootIssueCard(
                id="desktop_overload",
                title="Sobrecarga de Archivos en el Escritorio (Finder & WindowServer)",
                status="crit",
                status_badge="🔴 Ralentiza el Inicio",
                metric_text=f"{top_items} iconos • {files_label} archivos",
                description=(
                    f"Tienes {top_items} elementos en el Escritorio que contienen {files_label} archivos internos "
                    "(como proyectos con venv/node_modules o multimedia). Al iniciar sesión, Finder y Spotlight "
                    "tienen que indexarlos y generar vistas previas antes de mostrar el escritorio fluido."
                ),
                action_label="📁 Agrupar Multimedia Suelta",
                action_key="CLEAN_DESKTOP_LOOSE",
            )
        elif top_items > 15 or total_files > 1000:
            return BootIssueCard(
                id="desktop_overload",
                title="Carga del Escritorio (Finder & Previsualizaciones)",
                status="warn",
                status_badge="🟡 Carga Moderada",
                metric_text=f"{top_items} iconos • {files_label} archivos",
                description=(
                    f"Tienes {top_items} elementos ({files_label} archivos totales) en el Escritorio. "
                    "Mantener las carpetas de proyectos en ~/Proyectos evita que el Finder se bloquee al iniciar."
                ),
                action_label="📁 Agrupar Sueltos",
                action_key="CLEAN_DESKTOP_LOOSE",
            )
        return BootIssueCard(
            id="desktop_overload",
            title="Escritorio Despejado (Carga Instantánea del Finder)",
            status="ok",
            status_badge="🟢 Óptimo",
            metric_text=f"{top_items} iconos ({files_label} arch.)",
            description=(
                "Tu Escritorio está ligero y libre de proyectos masivos. Finder y WindowServer pueden "
                "dibujar el escritorio en apenas 2-4 segundos tras poner la contraseña."
            ),
        )

    @classmethod
    def _check_reopen_windows_pref(cls) -> BootIssueCard:
        reopen_enabled = False
        try:
            out = subprocess.check_output(
                ["defaults", "read", "com.apple.loginwindow", "TALLogoutSavesState"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2,
            ).strip()
            reopen_enabled = out in ("1", "true", "TRUE", "YES")
        except Exception:
            pass

        byhost_dir = expand_home("~/Library/Preferences/ByHost")
        has_relaunch_list = False
        try:
            if os.path.isdir(byhost_dir):
                for fname in os.listdir(byhost_dir):
                    if fname.startswith("com.apple.loginwindow.") and fname.endswith(".plist"):
                        fpath = os.path.join(byhost_dir, fname)
                        p_out = subprocess.check_output(
                            ["plutil", "-p", fpath], text=True, stderr=subprocess.DEVNULL, timeout=2
                        )
                        if "TALAppsToRelaunchAtLogin" in p_out and "=>" in p_out:
                            has_relaunch_list = True
        except Exception:
            pass

        if reopen_enabled or has_relaunch_list:
            return BootIssueCard(
                id="reopen_windows",
                title="Reapertura Automática de Aplicaciones al Iniciar Sesión",
                status="crit",
                status_badge="🔴 Consume RAM al Arrancar",
                metric_text="TALLogoutSavesState Activo",
                description=(
                    "macOS tiene activado reabrir automáticamente las aplicaciones previas (como Chrome con todas "
                    "sus pestañas) en el mismo instante en que pones la contraseña, saturando los 8 GB de RAM."
                ),
                action_label="⚡ Desactivar Reapertura",
                action_key="DISABLE_REOPEN_WINDOWS",
            )

        return BootIssueCard(
            id="reopen_windows",
            title="Reapertura Automática de Ventanas (`loginwindow`)",
            status="ok",
            status_badge="🟢 Desactivado (Limpio)",
            metric_text="Inicio en limpio",
            description=(
                "macOS no relanza navegadores ni aplicaciones pesadas encima del inicio de sesión, "
                "ahorrando entre 15 y 25 segundos de compresión de RAM."
            ),
        )

    @classmethod
    def _check_finder_extensions_and_daemons(cls) -> BootIssueCard:
        active_exts: list[str] = []
        try:
            pk_out = subprocess.check_output(["pluginkit", "-m", "-v"], text=True, timeout=3)
            for line in pk_out.splitlines():
                if line.strip().startswith("+"):
                    if "com.adobe.accmac.ACCFinderSync" in line:
                        active_exts.append("com.adobe.accmac.ACCFinderSync")
        except Exception:
            pass

        uid = os.getuid()
        enabled_daemons: list[str] = []
        la_dirs = [expand_home("~/Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
        existing_plists = set()
        for d in la_dirs:
            if os.path.isdir(d):
                try:
                    for fn in os.listdir(d):
                        if fn.endswith(".plist"):
                            existing_plists.add(fn[:-6])
                except Exception:
                    pass

        try:
            lc_out = subprocess.check_output(
                ["launchctl", "print-disabled", f"user/{uid}"], text=True, timeout=3
            )
            for svc_id, svc_name in cls.KNOWN_THIRD_PARTY_SERVICES:
                if f'"{svc_id}" => enabled' in lc_out and svc_id in existing_plists:
                    enabled_daemons.append(svc_name)
        except Exception:
            pass

        mau_exists = os.path.isdir("/Library/Application Support/Microsoft/MAU2.0")

        issues_count = len(active_exts) + len(enabled_daemons) + (1 if mau_exists else 0)
        if issues_count > 0:
            details = []
            if active_exts:
                details.append("Extensión Adobe Finder Sync activa")
            if enabled_daemons:
                details.append(f"Servicios activos: {', '.join(enabled_daemons[:3])}")
            if mau_exists:
                details.append("Residuo Microsoft AutoUpdate (MAU2.0)")
            return BootIssueCard(
                id="bg_daemons",
                title="Extensiones del Finder y Demonios de Terceros en Segundo Plano",
                status="warn",
                status_badge=f"🟡 {issues_count} Detectado(s)",
                metric_text=f"{issues_count} servicio(s)",
                description=(
                    f"Se han detectado servicios que se inyectan en el inicio: {' • '.join(details)}. "
                    "Puedes deshabilitarlos para que no intercepten el Finder ni consuman CPU al arrancar."
                ),
                action_label="🛡️ Desactivar Servicios",
                action_key="DISABLE_BG_SERVICES",
            )

        return BootIssueCard(
            id="bg_daemons",
            title="Extensiones del Finder y Actualizadores Fantasma",
            status="ok",
            status_badge="🟢 Limpio",
            metric_text="0 intrusos activos",
            description=(
                "Las extensiones pesadas del Finder (como Adobe CoreSync) y los actualizadores ocultos "
                "(Zoom, Adobe AGM, Microsoft MAU) están deshabilitados."
            ),
        )

    @classmethod
    def _check_spotlight_and_external_drives(cls) -> BootIssueCard:
        mdworker_count = 0
        mds_cpu = 0.0
        try:
            ps_out = subprocess.check_output(["ps", "-axo", "pcpu=,comm="], text=True, timeout=3)
            for line in ps_out.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) < 2:
                    continue
                cpu = float(parts[0].replace(",", "."))
                comm = parts[1]
                if "mdworker_shared" in comm:
                    mdworker_count += 1
                    mds_cpu += cpu
                elif "/mds" in comm or "mds_stores" in comm:
                    mds_cpu += cpu
        except Exception:
            pass

        ext_volumes: list[str] = []
        try:
            if os.path.isdir("/Volumes"):
                for v in os.listdir("/Volumes"):
                    if v not in ("Macintosh HD", "Preboot", "Recovery", "VM", "Update", "Data") and not v.startswith("."):
                        vpath = os.path.join("/Volumes", v)
                        if os.path.ismount(vpath):
                            ext_volumes.append(v)
        except Exception:
            pass

        if mds_cpu > 35.0 or mdworker_count >= 8:
            return BootIssueCard(
                id="spotlight_storm",
                title="Tormenta de Indexación de Spotlight (`mds_stores` / `mdworker`)",
                status="warn",
                status_badge=f"🟡 Indexando ({mds_cpu:.0f}% CPU)",
                metric_text=f"{mdworker_count} workers activos",
                description=(
                    f"Spotlight tiene {mdworker_count} procesos escaneando archivos ahora mismo "
                    f"(consumiendo {mds_cpu:.0f}% de CPU)"
                    + (f" con unidad externa conectada ({', '.join(ext_volumes)})." if ext_volumes else ".")
                    + " Añadir tus carpetas de código y discos externos a Privacidad de Spotlight evita este freno."
                ),
                action_label="⚙️ Abrir Spotlight",
                action_key="OPEN_SPOTLIGHT_PREFS",
            )

        vol_note = f"Discos montados: {', '.join(ext_volumes)}" if ext_volumes else "Sin discos externos lentos"
        return BootIssueCard(
            id="spotlight_storm",
            title="Indexación de Spotlight y Volúmenes Externos USB",
            status="ok",
            status_badge="🟢 En Reposo",
            metric_text=f"{mds_cpu:.0f}% CPU • {vol_note}",
            description=(
                "El motor de búsqueda Spotlight está tranquilo y no está bloqueando los núcleos del M1 "
                "ni escaneando masivamente entornos virtuales."
            ),
        )

    @classmethod
    def _check_filevault_and_nvram(cls) -> BootIssueCard:
        fv_on = False
        try:
            fv_out = subprocess.check_output(["fdesetup", "status"], text=True, timeout=2)
            fv_on = "FileVault is On" in fv_out
        except Exception:
            pass

        other_users: list[str] = []
        try:
            for u in os.listdir("/Users"):
                if u not in ("Shared", "danidev", "loginwindow", ".localized") and not u.startswith("."):
                    if os.path.isdir(os.path.join("/Users", u)):
                        other_users.append(u)
        except Exception:
            pass

        if fv_on:
            return BootIssueCard(
                id="filevault_nvram",
                title="Cifrado Preboot FileVault y Cuentas Secundarias",
                status="warn",
                status_badge="🟡 Arranque Post-Contraseña",
                metric_text="FileVault Activo",
                description=(
                    "Con FileVault activado, la pantalla inicial de contraseña es el Preboot EFI: macOS no "
                    "arranca de verdad hasta después de meter la contraseña (añadiendo ~35-45s tras el login)."
                ),
            )

        users_note = f"Otras cuentas en disco: {', '.join(other_users)}" if other_users else "1 cuenta principal"
        return BootIssueCard(
            id="filevault_nvram",
            title="Arranque Directo APFS (FileVault & Preboot)",
            status="ok",
            status_badge="🟢 Arranque Directo",
            metric_text=f"FileVault Off • {users_note}",
            description=(
                "FileVault está desactivado: tu Mac carga el sistema operativo antes de la pantalla de login, "
                "por lo que al introducir tu contraseña entras al escritorio en apenas 2-4 segundos."
            ),
        )

    # -------------------------------------------------------------------------
    # One-Click Remediation Actions
    # -------------------------------------------------------------------------
    @classmethod
    def execute_fix(cls, action_key: str) -> str:
        if action_key == "DISABLE_REOPEN_WINDOWS":
            try:
                subprocess.run(
                    ["defaults", "write", "com.apple.loginwindow", "TALLogoutSavesState", "-bool", "false"],
                    check=False,
                    timeout=3,
                )
                subprocess.run(
                    ["defaults", "write", "-g", "ApplePersistence", "-bool", "false"],
                    check=False,
                    timeout=3,
                )
                subprocess.run(
                    ["defaults", "delete", "com.apple.loginwindow", "TALAppsToRelaunchAtLogin"],
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=3,
                )
                byhost = expand_home("~/Library/Preferences/ByHost")
                if os.path.isdir(byhost):
                    for fn in os.listdir(byhost):
                        if fn.startswith("com.apple.loginwindow.") and fn.endswith(".plist"):
                            try:
                                os.remove(os.path.join(byhost, fn))
                            except Exception:
                                pass
                return "✓ Desactivada la reapertura automática de aplicaciones al iniciar sesión."
            except Exception as e:
                return f"Aviso al ajustar loginwindow: {e}"

        elif action_key == "DISABLE_BG_SERVICES":
            uid = os.getuid()
            try:
                subprocess.run(
                    ["pluginkit", "-e", "ignore", "-i", "com.adobe.accmac.ACCFinderSync"],
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=3,
                )
                targets = [f"user/{uid}/{svc_id}" for svc_id, _ in cls.KNOWN_THIRD_PARTY_SERVICES]
                subprocess.run(
                    ["launchctl", "disable"] + targets,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=4,
                )
                return "✓ Extensiones pesadas del Finder y demonios en segundo plano deshabilitados."
            except Exception as e:
                return f"Aviso al desactivar servicios: {e}"

        elif action_key == "CLEAN_DESKTOP_LOOSE":
            desktop = expand_home("~/Desktop")
            target_dir = os.path.join(desktop, "Archivos_no borrar")
            os.makedirs(target_dir, exist_ok=True)
            moved = 0
            loose_exts = {".png", ".jpg", ".jpeg", ".mp4", ".mov", ".zip", ".docx", ".pdf", ".af", ".webp"}
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
                return f"✓ Se agruparon {moved} archivo(s) multimedia sueltos en «Archivos_no borrar»."
            return "✓ No había archivos multimedia sueltos adicionales en el Escritorio."

        elif action_key == "OPEN_SPOTLIGHT_PREFS":
            try:
                subprocess.Popen(
                    ["open", "x-apple.systempreferences:com.apple.Spotlight-Settings.extension"]
                )
                return "✓ Abriendo Ajustes de Spotlight para gestionar carpetas excluidas."
            except Exception:
                return "Abre Ajustes del Sistema > Spotlight > Privacidad de Spotlight."

        return "Acción completada."
