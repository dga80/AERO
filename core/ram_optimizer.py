import os
import re
import signal
import subprocess
from dataclasses import dataclass

from core.utils import format_size, get_chip_name, get_total_ram_bytes, run_quick_macos_optimizations


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
    cpu_cores: int = 8
    cpu_usage_pct: int = 0
    gpu_device_pct: int = 0
    gpu_renderer_pct: int = 0
    gpu_tiler_pct: int = 0
    gpu_vram_bytes: int = 0
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
    """Monitors macOS Unified Memory / RAM, Swap usage, and groups multi-process apps
    so non-technical users can see what is eating their RAM and safely free background daemons.
    """

    # Background services/daemons that frequently bloat in RAM on macOS and are 100% safe
    # to terminate (macOS or the parent app restarts them cleanly on demand with tiny RAM).
    RECYCLABLE_DAEMONS: dict[str, str] = {
        "applespell": "Caché del corrector ortográfico de macOS. Se infla con el uso; reiniciarlo libera RAM al instante sin afectar nada.",
        "mediaanalysisd": "Analizador en segundo plano de caras y objetos en fotos/vídeos de macOS. Consume bastante RAM; es 100% seguro pausarlo.",
        "photoanalysisd": "Analizador en segundo plano de la fototeca de Fotos. 100% seguro pausarlo para recuperar RAM.",
        "mtlcompilerservice": "Servicio temporal de compilación gráfica Metal (GPU). Seguro de liberar.",
        "quicklookuiservice": "Generador de vistas previas (barra espaciadora) del Finder. Seguro de liberar.",
        "weather": "Widget del Tiempo de macOS corriendo en segundo plano. Seguro de liberar.",
        "home": "Servicio en segundo plano de la app Casa (HomeKit) de macOS. Seguro de liberar.",
        "coresync": "Demonio de sincronización en segundo plano de Adobe Creative Cloud.",
        "ccxprocess": "Proceso en segundo plano de Adobe Creative Cloud.",
        "adobecri": "Servicio de reportes de Adobe en segundo plano.",
        "adobecradaemon": "Demonio de diagnóstico de Adobe en segundo plano.",
        "adobeipcbroker": "Proceso intercomunicador de Adobe en segundo plano.",
        "creative cloud helper": "Asistente en segundo plano de Adobe Creative Cloud.",
        "cclibrary": "Servicio de bibliotecas en segundo plano de Adobe.",
        "edgeupdater": "Actualizador residual de Microsoft Edge en segundo plano.",
        "assistantservice": "Servicio residual en segundo plano de Snap Camera.",
    }

    # Core macOS & current session processes that should never be closed by the user
    PROTECTED_APPS = {
        "aero",
        "antigravity",
        "windowserver",
        "finder",
        "loginwindow",
        "controlcenter",
        "dock",
        "systemuiserver",
        "kernel_task",
        "mds_stores",
        "mdworker_shared",
        "com.apple.driverkit-applebcmwlan",
        "setstoreupdateservice",
        "sharingd",
        "siri ai",
    }

    APP_DESCRIPTIONS: dict[str, str] = {
        "Google Chrome": "Navegador web (suma la ventana principal, extensiones y todas las pestañas abiertas).",
        "Antigravity": "Tu entorno de desarrollo e IA actual (protegido para no cerrar tu sesión activa).",
        "AppleSpell": "Servicio del corrector ortográfico de macOS. Acumula RAM con las horas; puedes reciclarlo sin riesgo.",
        "mediaanalysisd": "Proceso de macOS que escanea fotos y vídeos buscando texto y caras en segundo plano. Puedes reciclarlo para ganar RAM.",
        "photoanalysisd": "Proceso de análisis de Fotos en segundo plano. Puedes reciclarlo para ganar RAM.",
        "WindowServer": "Motor gráfico de macOS que dibuja tus ventanas, escritorio y efectos visuales en pantalla.",
        "Finder": "Gestor de archivos y escritorio de tu Mac.",
        "Safari": "Navegador web de Apple.",
        "Siri AI": "Servicio de inteligencia del sistema de macOS.",
        "ControlCenter": "Barra de menús superior y Centro de Control de macOS.",
        "MTLCompilerService": "Compilador temporal de shaders gráficos para la GPU de tu Mac.",
        "mdworker_shared": "Indexador de búsqueda de Spotlight de macOS.",
        "mds_stores": "Base de datos de búsqueda rápida de Spotlight de macOS.",
        "SetStoreUpdateService": "Servicio interno del sistema de macOS.",
        "com.apple.DriverKit-AppleBCMWLAN": "Controlador de la tarjeta Wi-Fi de tu Mac.",
        "Weather": "Procesos en segundo plano del widget/app Clima de macOS.",
        "Home": "Procesos en segundo plano de la app Casa (HomeKit) de macOS.",
    }

    @classmethod
    def get_ram_health(cls) -> RamHealthSnapshot:
        """Reads total RAM, memory_pressure, vm_stat, and vm.swapusage on macOS."""
        total_ram = get_total_ram_bytes()
        chip_name = get_chip_name()

        swap_used = 0
        try:
            swap_out = subprocess.check_output(["sysctl", "vm.swapusage"], text=True, timeout=2)
            m = re.search(r"used\s*=\s*([\d.]+)([MGK])", swap_out)
            if m:
                val = float(m.group(1))
                unit = m.group(2)
                if unit == "G":
                    swap_used = int(val * (1024 ** 3))
                elif unit == "M":
                    swap_used = int(val * (1024 ** 2))
                elif unit == "K":
                    swap_used = int(val * 1024)
        except Exception:
            pass

        free_pct = 45
        try:
            mp_out = subprocess.check_output(["memory_pressure"], text=True, timeout=3)
            m_pct = re.search(r"System-wide memory free percentage:\s*(\d+)%", mp_out)
            if m_pct:
                free_pct = int(m_pct.group(1))
        except Exception:
            pass

        compressed_bytes = 0
        used_bytes = int(total_ram * (100 - free_pct) / 100)
        try:
            vm_out = subprocess.check_output(["vm_stat"], text=True, timeout=2)
            page_size = 16384
            m_ps = re.search(r"page size of (\d+) bytes", vm_out)
            if m_ps:
                page_size = int(m_ps.group(1))

            def get_pages(label: str) -> int:
                m_p = re.search(rf"{re.escape(label)}:\s+(\d+)\.", vm_out)
                return int(m_p.group(1)) if m_p else 0

            active_p = get_pages("Pages active")
            wired_p = get_pages("Pages wired down")
            comp_p = get_pages("Pages occupied by compressor")
            compressed_bytes = comp_p * page_size
            calc_used = (active_p + wired_p + comp_p) * page_size
            if calc_used > 0:
                used_bytes = min(calc_used, total_ram)
        except Exception:
            pass

        if free_pct >= 35 and swap_used < 500 * (1024 ** 2):
            badge = f"🟢 Presión Baja / Óptima ({free_pct}% margen libre)"
            color = "green"
            explanation = (
                f"Tu Mac ({chip_name} • {format_size(total_ram)}) respira con holgura. "
                f"RAM comprimida: {format_size(compressed_bytes)} • Swap en SSD: {format_size(swap_used)}."
            )
        elif free_pct >= 20 and swap_used < 2 * (1024 ** 3):
            badge = f"🟡 Presión Moderada ({free_pct}% margen libre)"
            color = "amber"
            explanation = (
                f"Tu RAM de {format_size(total_ram)} tiene carga media. "
                f"RAM comprimida: {format_size(compressed_bytes)} • Swap en SSD: {format_size(swap_used)}. "
                "Pulsa «🚀 Activar Modo Turbo RAM» para reciclar demonios en segundo plano."
            )
        else:
            badge = f"🔴 Presión Alta de RAM ({free_pct}% libre)"
            color = "red"
            explanation = (
                f"¡Tus {format_size(total_ram)} están al límite y macOS usa {format_size(swap_used)} de tu SSD como Swap! "
                "Pulsa «🚀 Activar Modo Turbo RAM» o cierra aplicaciones que no uses."
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
            **cls._read_cpu_and_gpu_metrics(),
        )

    @classmethod
    def _read_cpu_and_gpu_metrics(cls) -> dict:
        """Reads Apple Silicon CPU load average, core count, and live IOAccelerator GPU telemetry."""
        cpu_cores = os.cpu_count() or 8
        load_1m = 0.0
        try:
            load_1m, _, _ = os.getloadavg()
        except Exception:
            pass

        gpu_dev = 0
        gpu_rend = 0
        gpu_tiler = 0
        gpu_vram = 0
        try:
            io_out = subprocess.check_output(
                ["ioreg", "-r", "-d", "1", "-c", "IOAccelerator"], text=True, timeout=2
            )
            m_dev = re.search(r'"Device Utilization %"\s*=\s*(\d+)', io_out)
            m_rend = re.search(r'"Renderer Utilization %"\s*=\s*(\d+)', io_out)
            m_til = re.search(r'"Tiler Utilization %"\s*=\s*(\d+)', io_out)
            m_mem = re.search(r'"In use system memory"\s*=\s*(\d+)', io_out)
            if m_dev:
                gpu_dev = int(m_dev.group(1))
            if m_rend:
                gpu_rend = int(m_rend.group(1))
            if m_til:
                gpu_tiler = int(m_til.group(1))
            if m_mem:
                gpu_vram = int(m_mem.group(1))
        except Exception:
            pass

        top_cpu_name = "En reposo"
        total_cpu_sum = 0.0
        try:
            ps_out = subprocess.check_output(["ps", "-axo", "pcpu=,comm="], text=True, timeout=2)
            best_cpu = 0.0
            for line in ps_out.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) < 2:
                    continue
                val = float(parts[0].replace(",", "."))
                total_cpu_sum += val
                if val > best_cpu:
                    best_cpu = val
                    g_name, _ = cls._resolve_group_name(parts[1].strip())
                    top_cpu_name = f"{g_name} ({val:.0f}%)"
        except Exception:
            pass

        cpu_pct = min(100, max(1, int(round(total_cpu_sum / max(1, cpu_cores)))))
        return {
            "cpu_load_1m": round(load_1m, 2),
            "cpu_cores": cpu_cores,
            "cpu_usage_pct": cpu_pct,
            "gpu_device_pct": gpu_dev,
            "gpu_renderer_pct": gpu_rend,
            "gpu_tiler_pct": gpu_tiler,
            "gpu_vram_bytes": gpu_vram,
            "top_cpu_process": top_cpu_name,
        }

    @classmethod
    def get_top_ram_groups(cls, limit: int = 18) -> list[AppRamGroup]:
        """Lists running processes via `ps -axo pid,rss,pcpu,comm` and groups helpers under their parent App."""
        groups: dict[str, AppRamGroup] = {}
        my_pid = os.getpid()

        try:
            out = subprocess.check_output(["ps", "-axo", "pid=,rss=,pcpu=,comm="], text=True, timeout=4)
        except Exception:
            return []

        for line in out.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
                rss_kb = int(parts[1])
                cpu_val = float(parts[2].replace(",", "."))
                comm = parts[3].strip()
            except ValueError:
                continue

            if pid == my_pid or (rss_kb < 2048 and cpu_val < 5.0):
                continue

            rss_bytes = rss_kb * 1024
            group_name, category = cls._resolve_group_name(comm)
            lower_group = group_name.lower()

            if lower_group == "aero":
                continue

            is_recyclable = any(k == lower_group or k in lower_group for k in cls.RECYCLABLE_DAEMONS)
            is_protected = any(p == lower_group for p in cls.PROTECTED_APPS)

            if group_name not in groups:
                desc = cls._get_description(group_name, comm, is_recyclable)
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

        sorted_groups = sorted(groups.values(), key=lambda x: x.total_rss_bytes, reverse=True)
        return sorted_groups[:limit]

    @staticmethod
    def _resolve_group_name(comm_path: str) -> tuple[str, str]:
        """Extracts the top-level `.app` name or clean service name from a full command path."""
        m_app = re.search(r"/(?:Applications|CoreServices|Services)/([^/]+?)\.app/", comm_path)
        if m_app:
            app_title = m_app.group(1)
            if "/System/" in comm_path:
                return app_title, "Servicio macOS"
            return app_title, "Aplicación"

        base = os.path.basename(comm_path)
        if base.endswith(".xpc"):
            base = base[:-4]
        if "/System/" in comm_path or "/usr/" in comm_path or base.startswith("com.apple."):
            return base, "Servicio macOS"
        return base, "Segundo Plano"

    @classmethod
    def _get_description(cls, group_name: str, comm_path: str, is_recyclable: bool) -> str:
        if group_name in cls.APP_DESCRIPTIONS:
            return cls.APP_DESCRIPTIONS[group_name]
        lower_g = group_name.lower()
        for key, desc in cls.RECYCLABLE_DAEMONS.items():
            if key in lower_g or key in comm_path.lower():
                return desc
        if is_recyclable:
            return "Proceso en segundo plano que puede reciclarse para liberar memoria RAM."
        if "/System/" in comm_path:
            return "Componente del sistema operativo macOS."
        return f"Memoria unificada utilizada por «{group_name}» y sus subprocesos."

    @classmethod
    def free_process_group(cls, group: AppRamGroup) -> tuple[bool, int, str]:
        """Safely terminates a recyclable daemon or quits a user application to free RAM."""
        if group.is_protected:
            return False, 0, f"«{group.app_name}» está protegido para no interrumpir tu sesión."

        freed_estimate = group.total_rss_bytes
        killed_any = False

        if group.is_recyclable_daemon:
            for pid in group.pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_any = True
                except Exception:
                    pass
        else:
            try:
                subprocess.run(
                    ["osascript", "-e", f'tell application "{group.app_name}" to quit'],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                killed_any = True
            except Exception:
                pass

            if not killed_any:
                for pid in group.pids:
                    try:
                        os.kill(pid, signal.SIGTERM)
                        killed_any = True
                    except Exception:
                        pass

        if killed_any:
            return True, freed_estimate, f"✓ Se liberaron ~{format_size(freed_estimate)} de RAM de «{group.app_name}»."
        return False, 0, f"No fue posible detener «{group.app_name}» (gestionado por macOS)."

    @classmethod
    def run_turbo_ram_boost(cls) -> tuple[int, int, str]:
        """Finds all running recyclable background daemons (AppleSpell, mediaanalysisd,
        photoanalysisd, MTLCompilerService, QuickLookUIService, Weather, Home, Adobe helpers),
        terminates them safely so macOS reclaims their bloated RAM, and runs QuickLook + DNS optimizations.
        """
        groups = cls.get_top_ram_groups(limit=60)
        total_freed = 0
        count_recycled = 0

        for g in groups:
            if g.is_recyclable_daemon and not g.is_protected:
                ok, freed, _ = cls.free_process_group(g)
                if ok:
                    total_freed += freed
                    count_recycled += 1

        run_quick_macos_optimizations()

        if count_recycled > 0:
            msg = (
                f"🚀 Modo Turbo RAM completado: {count_recycled} demonio(s) en segundo plano reciclados "
                f"(~{format_size(total_freed)} de RAM recuperados) + Finder y DNS optimizados."
            )
        else:
            msg = (
                "🚀 Modo Turbo RAM completado: Tus demonios en segundo plano ya estaban limpios "
                "+ Finder y DNS optimizados."
            )
        return count_recycled, total_freed, msg
