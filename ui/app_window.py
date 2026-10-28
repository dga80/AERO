import queue
import threading
from typing import Callable, Optional
import customtkinter as ctk

from core.cleaner import CleanResult, SafeCleaner
from core.models import ModuleType, SafetyLevel, ScanItem, ScanSummary
from core.ram_optimizer import AppRamGroup, RamHealthSnapshot, RamOptimizer
from core.scanner import SystemDataScanner
from core.utils import (
    empty_windows_trash,
    format_size,
    get_windows_trash_size,
    open_windows_trash,
    reveal_in_explorer,
    run_quick_windows_optimizations,
)


# Dark Mode Palette (AERO Signature Theme)
COLOR_BG_MAIN = "#161618"
COLOR_BG_SIDEBAR = "#1E1E22"
COLOR_BG_CARD = "#242429"
COLOR_BG_CARD_HOVER = "#2C2C33"
COLOR_ACCENT_BLUE = "#0A84FF"
COLOR_ACCENT_BLUE_HOVER = "#0070E0"
COLOR_DANGER_RED = "#E0352B"
COLOR_DANGER_RED_HOVER = "#C2271E"
COLOR_DISABLED_BTN_BG = "#2A2A30"
COLOR_DISABLED_BTN_TEXT = "#7A7A85"
COLOR_WARNING_AMBER = "#FF9F0A"
COLOR_SUCCESS_GREEN = "#30D158"
COLOR_TEXT_PRIMARY = "#F5F5F7"
COLOR_TEXT_SECONDARY = "#98989D"
COLOR_BORDER = "#323238"

FONT_DISPLAY = "Segoe UI"
FONT_TEXT = "Segoe UI"
FONT_MONO = "Consolas"


class ConfirmTrashDialog(ctk.CTkToplevel):
    """Native-styled modal confirmation dialog before sending items to the Windows Recycle Bin."""

    def __init__(
        self,
        parent: ctk.CTk,
        items_count: int,
        total_size_str: str,
        active_apps_selected: list[str],
        on_confirm: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self.title("Confirmar limpieza segura")
        height = 330 if active_apps_selected else 250
        self.geometry(f"490x{height}")
        self.resizable(False, False)
        self.configure(fg_color=COLOR_BG_SIDEBAR)
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 245
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (height // 2)
        self.geometry(f"+{max(x, 100)}+{max(y, 100)}")

        self.on_confirm = on_confirm

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=24, pady=20)

        title_lbl = ctk.CTkLabel(
            container,
            text=f"¿Enviar {items_count} elemento(s) a la Papelera de reciclaje?",
            font=ctk.CTkFont(family=FONT_DISPLAY, size=17, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        title_lbl.pack(fill="x", pady=(0, 8))

        desc_lbl = ctk.CTkLabel(
            container,
            text=(
                f"Espacio que se moverá a la Papelera: {total_size_str}\n"
                "Todo se envía a la Papelera de reciclaje de Windows (no se destruye permanentemente), "
                "por lo que siempre podrás restaurarlo o vaciar la Papelera después."
            ),
            font=ctk.CTkFont(family=FONT_TEXT, size=13),
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            wraplength=440,
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(0, 10))

        if active_apps_selected:
            apps_preview = ", ".join(active_apps_selected[:3])
            if len(active_apps_selected) > 3:
                apps_preview += f" (+{len(active_apps_selected) - 3} más)"
            warn_frame = ctk.CTkFrame(
                container,
                fg_color="#3D1C1A",
                corner_radius=8,
                border_width=1,
                border_color=COLOR_DANGER_RED,
            )
            warn_frame.pack(fill="x", pady=(0, 12))
            warn_lbl = ctk.CTkLabel(
                warn_frame,
                text=(
                    f"🛑 ¡ATENCIÓN! Has marcado carpetas de programas que sigues teniendo instalados ({apps_preview}).\n"
                    "Si las borras, podrías perder configuraciones, perfiles o sesiones de esos programas."
                ),
                font=ctk.CTkFont(family=FONT_TEXT, size=12, weight="bold"),
                text_color="#FF8A80",
                justify="left",
                wraplength=415,
            )
            warn_lbl.pack(padx=12, pady=10, anchor="w")

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(fill="x", side="bottom")

        cancel_btn = ctk.CTkButton(
            btn_frame,
            text="Cancelar",
            fg_color="#3A3A40",
            hover_color="#484850",
            text_color=COLOR_TEXT_PRIMARY,
            width=120,
            height=36,
            corner_radius=8,
            command=self.destroy,
        )
        cancel_btn.pack(side="right", padx=(10, 0))

        confirm_btn = ctk.CTkButton(
            btn_frame,
            text="Sí, mover a la Papelera",
            fg_color=COLOR_DANGER_RED,
            hover_color=COLOR_DANGER_RED_HOVER,
            text_color="#FFFFFF",
            font=ctk.CTkFont(family=FONT_TEXT, size=13, weight="bold"),
            width=190,
            height=36,
            corner_radius=8,
            command=self._confirm,
        )
        confirm_btn.pack(side="right")

    def _confirm(self) -> None:
        self.grab_release()
        self.destroy()
        self.on_confirm()


class ConfirmEmptyTrashDialog(ctk.CTkToplevel):
    """Modal confirmation before permanently emptying the Windows Recycle Bin."""

    def __init__(
        self,
        parent: ctk.CTk,
        trash_size_str: str,
        on_confirm: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self.title("Vaciar Papelera de reciclaje")
        self.geometry("460x235")
        self.resizable(False, False)
        self.configure(fg_color=COLOR_BG_SIDEBAR)
        self.transient(parent)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 230
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 118
        self.geometry(f"+{max(x, 100)}+{max(y, 100)}")

        self.on_confirm = on_confirm

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=24, pady=20)

        ctk.CTkLabel(
            container,
            text=f"¿Vaciar definitivamente la Papelera ({trash_size_str})?",
            font=ctk.CTkFont(family=FONT_DISPLAY, size=16, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(
            container,
            text=(
                "Al vaciar la Papelera de reciclaje de Windows, estos archivos se eliminarán de forma definitiva "
                "y los gigas pasarán inmediatamente a estar libres en tu disco NTFS (C:)."
            ),
            font=ctk.CTkFont(family=FONT_TEXT, size=13),
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            wraplength=410,
            anchor="w",
        ).pack(fill="x", pady=(0, 14))

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(fill="x", side="bottom")

        ctk.CTkButton(
            btn_frame,
            text="Cancelar",
            fg_color="#3A3A40",
            hover_color="#484850",
            text_color=COLOR_TEXT_PRIMARY,
            width=115,
            height=35,
            corner_radius=8,
            command=self.destroy,
        ).pack(side="right", padx=(10, 0))

        ctk.CTkButton(
            btn_frame,
            text="Vaciar Papelera ahora",
            fg_color=COLOR_DANGER_RED,
            hover_color=COLOR_DANGER_RED_HOVER,
            text_color="#FFFFFF",
            font=ctk.CTkFont(family=FONT_TEXT, size=13, weight="bold"),
            width=185,
            height=35,
            corner_radius=8,
            command=self._confirm,
        ).pack(side="right")

    def _confirm(self) -> None:
        self.grab_release()
        self.destroy()
        self.on_confirm()


class AeroSystemCleanerApp(ctk.CTk):
    """Main CustomTkinter application window for Windows NTFS System Data analysis, cleaning & Turbo RAM optimization."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.title("AERO PC — Limpiador NTFS y Turbo RAM (Windows)")
        self.geometry("1180x790")
        self.minsize(1040, 690)
        self.configure(fg_color=COLOR_BG_MAIN)

        # State
        self.scanner = SystemDataScanner()
        self.ui_queue: queue.Queue = queue.Queue()
        self.is_busy = False

        self.all_items: list[ScanItem] = []
        self.tm_snapshots: list[str] = []
        self.trash_bytes: int = 0
        self.ram_health: Optional[RamHealthSnapshot] = None
        self.ram_groups: list[AppRamGroup] = []

        self.active_filter: ModuleType = ModuleType.ALL
        self.checkbox_vars: dict[str, ctk.BooleanVar] = {}
        self.nav_buttons: dict[ModuleType, ctk.CTkButton] = {}
        self.nav_badges: dict[ModuleType, ctk.CTkLabel] = {}

        self._build_layout()
        self._poll_ui_queue()
        # Load initial RAM & Recycle Bin badges in background
        self._refresh_ram_data_async(render_when_done=False)

    # -------------------------------------------------------------------------
    # Layout Construction
    # -------------------------------------------------------------------------
    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=0, minsize=310)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_panel()

    def _build_sidebar(self) -> None:
        self.sidebar = ctk.CTkFrame(
            self,
            fg_color=COLOR_BG_SIDEBAR,
            corner_radius=0,
            width=310,
            border_width=1,
            border_color=COLOR_BORDER,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # App Header
        header_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(16, 8))

        app_title = ctk.CTkLabel(
            header_frame,
            text="AERO PC",
            font=ctk.CTkFont(family=FONT_DISPLAY, size=22, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        app_title.pack(fill="x")

        app_sub = ctk.CTkLabel(
            header_frame,
            text="Limpiador NTFS + Turbo RAM (Windows)",
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        )
        app_sub.pack(fill="x", pady=(1, 0))

        # Total Detected Summary Card
        summary_card = ctk.CTkFrame(
            self.sidebar,
            fg_color=COLOR_BG_CARD,
            corner_radius=12,
            border_width=1,
            border_color=COLOR_BORDER,
        )
        summary_card.pack(fill="x", padx=16, pady=(2, 8))

        ctk.CTkLabel(
            summary_card,
            text="TOTAL DETECTADO (FÍSICO NTFS)",
            font=ctk.CTkFont(family=FONT_TEXT, size=10, weight="bold"),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        ).pack(fill="x", padx=14, pady=(8, 1))

        self.total_gb_label = ctk.CTkLabel(
            summary_card,
            text="0.00 GB",
            font=ctk.CTkFont(family=FONT_DISPLAY, size=25, weight="bold"),
            text_color=COLOR_ACCENT_BLUE,
            anchor="w",
        )
        self.total_gb_label.pack(fill="x", padx=14)

        self.safe_reclaim_label = ctk.CTkLabel(
            summary_card,
            text="🟢 100% Seguro limpiar: 0 B",
            font=ctk.CTkFont(family=FONT_TEXT, size=12, weight="bold"),
            text_color=COLOR_SUCCESS_GREEN,
            anchor="w",
        )
        self.safe_reclaim_label.pack(fill="x", padx=14, pady=(2, 1))

        self.selected_summary_label = ctk.CTkLabel(
            summary_card,
            text="Marcado ahora: 0 B (0 elem.)",
            font=ctk.CTkFont(family=FONT_TEXT, size=11),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        )
        self.selected_summary_label.pack(fill="x", padx=14, pady=(0, 8))

        # Module Filters Section
        ctk.CTkLabel(
            self.sidebar,
            text="MÓDULOS Y RENDIMIENTO",
            font=ctk.CTkFont(family=FONT_TEXT, size=10, weight="bold"),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        ).pack(fill="x", padx=20, pady=(2, 3))

        modules_meta = [
            (ModuleType.ALL, "Todos los Resultados"),
            (ModuleType.CACHES_LOGS, "1. Cachés y Temporales"),
            (ModuleType.DEV_JUNK, "2. Desarrollo e IA"),
            (ModuleType.APP_REMNANTS, "3. Restos de Programas"),
            (ModuleType.DOWNLOADS_TM, "4. Descargas y Restauración"),
            (ModuleType.OPTIMIZATION, "5. Inicio y Optimización"),
            (ModuleType.RAM_MONITOR, "🚀 6. Monitor y Turbo RAM"),
        ]

        for mod, title in modules_meta:
            row_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
            row_frame.pack(fill="x", padx=14, pady=1)

            is_ram = mod == ModuleType.RAM_MONITOR
            btn = ctk.CTkButton(
                row_frame,
                text=title,
                anchor="w",
                height=31,
                corner_radius=8,
                font=ctk.CTkFont(
                    family=FONT_TEXT,
                    size=12,
                    weight="bold" if is_ram else "normal",
                ),
                fg_color=COLOR_ACCENT_BLUE if mod == ModuleType.ALL else "transparent",
                hover_color=COLOR_BG_CARD_HOVER,
                text_color=COLOR_SUCCESS_GREEN if is_ram else COLOR_TEXT_PRIMARY,
                command=lambda m=mod: self._set_module_filter(m),
            )
            btn.pack(side="left", fill="x", expand=True)

            badge = ctk.CTkLabel(
                row_frame,
                text="RAM PC" if is_ram else "0 B",
                font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
                text_color=COLOR_SUCCESS_GREEN if is_ram else COLOR_TEXT_SECONDARY,
                width=64,
                anchor="e",
            )
            badge.pack(side="right", padx=(6, 4))

            self.nav_buttons[mod] = btn
            self.nav_badges[mod] = badge

        # Windows Recycle Bin Card with Open & Empty buttons
        self.trash_card = ctk.CTkFrame(
            self.sidebar,
            fg_color=COLOR_BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_BORDER,
        )
        self.trash_card.pack(fill="x", padx=16, pady=(8, 4))

        trash_top = ctk.CTkFrame(self.trash_card, fg_color="transparent")
        trash_top.pack(fill="x", padx=12, pady=(7, 2))

        ctk.CTkLabel(
            trash_top,
            text="🗑️ Papelera de reciclaje",
            font=ctk.CTkFont(family=FONT_TEXT, size=12, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(side="left")

        self.trash_size_label = ctk.CTkLabel(
            trash_top,
            text="0 B",
            font=ctk.CTkFont(family=FONT_DISPLAY, size=13, weight="bold"),
            text_color=COLOR_WARNING_AMBER,
            anchor="e",
        )
        self.trash_size_label.pack(side="right")

        ctk.CTkLabel(
            self.trash_card,
            text="El espacio vuelve a tu disco NTFS al vaciar la Papelera.",
            font=ctk.CTkFont(family=FONT_TEXT, size=10),
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            wraplength=250,
            anchor="w",
        ).pack(fill="x", padx=12, pady=(0, 5))

        trash_btns = ctk.CTkFrame(self.trash_card, fg_color="transparent")
        trash_btns.pack(fill="x", padx=12, pady=(0, 7))

        ctk.CTkButton(
            trash_btns,
            text="Ver Papelera",
            font=ctk.CTkFont(family=FONT_TEXT, size=11),
            fg_color="#32323A",
            hover_color="#42424E",
            text_color=COLOR_TEXT_PRIMARY,
            height=27,
            width=105,
            corner_radius=6,
            command=open_windows_trash,
        ).pack(side="left")

        self.empty_trash_btn = ctk.CTkButton(
            trash_btns,
            text="Vaciar Papelera",
            font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
            fg_color=COLOR_DISABLED_BTN_BG,
            hover_color=COLOR_DANGER_RED_HOVER,
            text_color="#FFFFFF",
            text_color_disabled=COLOR_DISABLED_BTN_TEXT,
            height=27,
            width=130,
            corner_radius=6,
            state="disabled",
            command=self._prompt_empty_windows_trash,
        )
        self.empty_trash_btn.pack(side="right")

        # System Restore / Hibernation Card (Module 4)
        self.tm_card = ctk.CTkFrame(
            self.sidebar,
            fg_color=COLOR_BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_BORDER,
        )
        self.tm_card.pack(fill="x", side="bottom", padx=16, pady=10)

        ctk.CTkLabel(
            self.tm_card,
            text="⏱ Restauración e Hibernación",
            font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x", padx=12, pady=(6, 1))

        self.tm_status_label = ctk.CTkLabel(
            self.tm_card,
            text="Analiza para detectar copias sombra (VSS) e hibernación en C:.",
            font=ctk.CTkFont(family=FONT_TEXT, size=10),
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            wraplength=250,
            anchor="w",
        )
        self.tm_status_label.pack(fill="x", padx=12, pady=(1, 6))

    def _build_main_panel(self) -> None:
        self.main_panel = ctk.CTkFrame(self, fg_color=COLOR_BG_MAIN, corner_radius=0)
        self.main_panel.grid(row=0, column=1, sticky="nsew")
        self.main_panel.grid_rowconfigure(2, weight=1)
        self.main_panel.grid_columnconfigure(0, weight=1)

        # Top Action Bar
        top_bar = ctk.CTkFrame(
            self.main_panel,
            fg_color=COLOR_BG_SIDEBAR,
            corner_radius=12,
            border_width=1,
            border_color=COLOR_BORDER,
        )
        top_bar.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        self.scan_btn = ctk.CTkButton(
            top_bar,
            text="🔍 Analizar Datos del Sistema",
            font=ctk.CTkFont(family=FONT_TEXT, size=13, weight="bold"),
            fg_color=COLOR_ACCENT_BLUE,
            hover_color=COLOR_ACCENT_BLUE_HOVER,
            text_color="#FFFFFF",
            height=38,
            corner_radius=8,
            width=225,
            command=self._start_scan_thread,
        )
        self.scan_btn.pack(side="left", padx=(14, 10), pady=12)

        self.select_safe_btn = ctk.CTkButton(
            top_bar,
            text="✅ Autoseleccionar 100% Seguros",
            font=ctk.CTkFont(family=FONT_TEXT, size=12, weight="bold"),
            fg_color="#1F3D2B",
            hover_color="#28523A",
            text_color=COLOR_SUCCESS_GREEN,
            text_color_disabled=COLOR_DISABLED_BTN_TEXT,
            height=38,
            corner_radius=8,
            width=225,
            command=self._select_safe_items,
            state="disabled",
        )
        self.select_safe_btn.pack(side="left", padx=(0, 8), pady=12)

        self.clear_sel_btn = ctk.CTkButton(
            top_bar,
            text="Desmarcar Todo",
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            fg_color="#2E2E36",
            hover_color="#3A3A44",
            text_color=COLOR_TEXT_PRIMARY,
            text_color_disabled=COLOR_DISABLED_BTN_TEXT,
            height=38,
            corner_radius=8,
            width=120,
            command=self._deselect_all,
            state="disabled",
        )
        self.clear_sel_btn.pack(side="left", pady=12)

        self.trash_btn = ctk.CTkButton(
            top_bar,
            text="🗑️ Mover a la Papelera (0)",
            font=ctk.CTkFont(family=FONT_TEXT, size=13, weight="bold"),
            fg_color=COLOR_DISABLED_BTN_BG,
            hover_color=COLOR_DANGER_RED_HOVER,
            text_color="#FFFFFF",
            text_color_disabled=COLOR_DISABLED_BTN_TEXT,
            height=38,
            corner_radius=8,
            width=225,
            command=self._prompt_clean_selected,
            state="disabled",
        )
        self.trash_btn.pack(side="right", padx=14, pady=12)

        # Status & Progress Bar Row
        status_frame = ctk.CTkFrame(self.main_panel, fg_color="transparent")
        status_frame.grid(row=1, column=0, sticky="ew", padx=22, pady=(0, 8))
        status_frame.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Listo. Analiza el disco o entra en «🚀 6. Monitor y Turbo RAM» a la izquierda.",
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        )
        self.status_label.grid(row=0, column=0, sticky="w")

        self.count_label = ctk.CTkLabel(
            status_frame,
            text="0 elementos mostrados",
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="e",
        )
        self.count_label.grid(row=0, column=1, sticky="e")

        self.progress_bar = ctk.CTkProgressBar(
            status_frame,
            height=6,
            corner_radius=3,
            progress_color=COLOR_ACCENT_BLUE,
        )
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.progress_bar.set(0)

        # Scrollable Results List
        self.results_scroll = ctk.CTkScrollableFrame(
            self.main_panel,
            fg_color=COLOR_BG_SIDEBAR,
            corner_radius=12,
            border_width=1,
            border_color=COLOR_BORDER,
        )
        self.results_scroll.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.results_scroll.grid_columnconfigure(0, weight=1)

        self._render_empty_state(
            "Haz clic en «🔍 Analizar Datos del Sistema» para escanear tu disco NTFS (C:),\n"
            "o haz clic en «🚀 6. Monitor y Turbo RAM» en el menú izquierdo para optimizar tu RAM en tiempo real."
        )

    # -------------------------------------------------------------------------
    # Threading & Asynchronous Queue Communication
    # -------------------------------------------------------------------------
    def _poll_ui_queue(self) -> None:
        try:
            while True:
                msg_type, payload = self.ui_queue.get_nowait()
                if msg_type == "PROGRESS":
                    text, val = payload
                    self.status_label.configure(text=text)
                    self.progress_bar.set(val)
                elif msg_type == "SCAN_DONE":
                    self._on_scan_complete(payload)
                elif msg_type == "CLEAN_DONE":
                    self._on_clean_complete(payload)
                elif msg_type == "EMPTY_TRASH_DONE":
                    self._on_empty_trash_complete(payload)
                elif msg_type == "QUICK_OPT_DONE":
                    self.status_label.configure(text=payload)
                elif msg_type == "RAM_DATA_READY":
                    health, groups, should_render, custom_msg, trash_sz = payload
                    self.ram_health = health
                    self.ram_groups = groups
                    if trash_sz is not None:
                        self._update_trash_card_ui(trash_sz)
                    ram_badge = self.nav_badges.get(ModuleType.RAM_MONITOR)
                    if ram_badge and health:
                        ram_badge.configure(text=f"{health.free_percentage}% libre")
                    if custom_msg:
                        self.status_label.configure(text=custom_msg)
                    if should_render and self.active_filter == ModuleType.RAM_MONITOR:
                        self._render_results_list()
        except queue.Empty:
            pass
        finally:
            self.after(60, self._poll_ui_queue)

    def _refresh_ram_data_async(
        self, render_when_done: bool = True, custom_status: Optional[str] = None
    ) -> None:
        if render_when_done and not custom_status:
            self.status_label.configure(text="Analizando Memoria RAM física, paginación (Swap) y procesos activos...")

        def worker() -> None:
            health = RamOptimizer.get_ram_health()
            groups = RamOptimizer.get_top_ram_groups(limit=18)
            trash_sz = get_windows_trash_size()
            self.ui_queue.put(("RAM_DATA_READY", (health, groups, render_when_done, custom_status, trash_sz)))

        threading.Thread(target=worker, daemon=True).start()

    def _start_scan_thread(self) -> None:
        if self.is_busy:
            return
        self.is_busy = True
        self.scan_btn.configure(state="disabled", text="⏳ Escaneando...")
        self._set_trash_button_state(0)
        self.select_safe_btn.configure(state="disabled")
        self.clear_sel_btn.configure(state="disabled")
        self.progress_bar.set(0.03)

        def worker() -> None:
            summary = self.scanner.run_full_scan(
                progress_callback=lambda msg, p: self.ui_queue.put(("PROGRESS", (msg, p)))
            )
            self.ui_queue.put(("SCAN_DONE", summary))

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _on_scan_complete(self, summary: ScanSummary) -> None:
        self.is_busy = False
        self.scan_btn.configure(state="normal", text="🔍 Analizar Datos del Sistema")

        self.all_items = summary.items
        self.tm_snapshots = summary.tm_snapshots
        self.trash_bytes = summary.trash_bytes
        self.checkbox_vars.clear()

        for item in self.all_items:
            item.selected = item.safety_level == SafetyLevel.SAFE
            self.checkbox_vars[item.id] = ctk.BooleanVar(value=item.selected)

        self.total_gb_label.configure(text=format_size(summary.total_bytes))
        safe_total = sum(i.size_bytes for i in self.all_items if i.safety_level == SafetyLevel.SAFE)
        self.safe_reclaim_label.configure(text=f"🟢 100% Seguro limpiar: {format_size(safe_total)}")

        for mod, badge in self.nav_badges.items():
            if mod == ModuleType.RAM_MONITOR:
                continue
            mod_bytes = summary.module_bytes.get(mod, 0)
            badge.configure(text=format_size(mod_bytes))

        self._update_trash_card_ui(self.trash_bytes)
        self._refresh_ram_data_async(render_when_done=(self.active_filter == ModuleType.RAM_MONITOR))

        snap_count = len(self.tm_snapshots)
        if snap_count == 0:
            self.tm_status_label.configure(
                text="✓ Sin espacio retenido por copias sombra en C:.",
                text_color=COLOR_SUCCESS_GREEN,
            )
        else:
            sample = "\n".join(f"• {s}" for s in self.tm_snapshots[:2])
            more = f"\n(+{snap_count - 2} más)" if snap_count > 2 else ""
            self.tm_status_label.configure(
                text=f"ℹ️ Reservado por el sistema:\n{sample}{more}",
                text_color=COLOR_WARNING_AMBER,
            )

        if self.all_items:
            self.select_safe_btn.configure(state="normal")
            self.clear_sel_btn.configure(state="normal")

        self._update_selected_summary()
        self._render_results_list()
        self.status_label.configure(
            text=(
                f"Análisis completado: Hemos marcado automáticamente {format_size(safe_total)} "
                "que son 100% seguros de enviar a la Papelera de reciclaje."
            )
        )
        self.progress_bar.set(1.0)

    def _update_trash_card_ui(self, trash_bytes: int) -> None:
        self.trash_bytes = trash_bytes
        self.trash_size_label.configure(
            text=format_size(trash_bytes),
            text_color=COLOR_WARNING_AMBER if trash_bytes > 0 else COLOR_SUCCESS_GREEN,
        )
        if trash_bytes > 0 and not self.is_busy:
            self.empty_trash_btn.configure(
                state="normal",
                fg_color=COLOR_DANGER_RED,
                text_color="#FFFFFF",
            )
        else:
            self.empty_trash_btn.configure(
                state="disabled",
                fg_color=COLOR_DISABLED_BTN_BG,
                text_color_disabled=COLOR_DISABLED_BTN_TEXT,
            )

    def _prompt_empty_windows_trash(self) -> None:
        if self.is_busy or self.trash_bytes <= 0:
            return
        ConfirmEmptyTrashDialog(
            parent=self,
            trash_size_str=format_size(self.trash_bytes),
            on_confirm=self._start_empty_trash_thread,
        )

    def _start_empty_trash_thread(self) -> None:
        self.is_busy = True
        self.empty_trash_btn.configure(
            state="disabled",
            fg_color=COLOR_DISABLED_BTN_BG,
            text="Vaciando...",
        )
        self.status_label.configure(text="Vaciando la Papelera de reciclaje de Windows y liberando espacio NTFS...")

        def worker() -> None:
            ok, msg = empty_windows_trash()
            remaining = get_windows_trash_size()
            self.ui_queue.put(("EMPTY_TRASH_DONE", (ok, msg, remaining)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_empty_trash_complete(self, payload: tuple[bool, str, int]) -> None:
        self.is_busy = False
        _, msg, remaining = payload
        self.empty_trash_btn.configure(text="Vaciar Papelera")
        self._update_trash_card_ui(remaining)
        self._update_selected_summary()
        self.status_label.configure(text=f"✓ {msg}")

    # -------------------------------------------------------------------------
    # Filtering & Rendering
    # -------------------------------------------------------------------------
    def _set_module_filter(self, module: ModuleType) -> None:
        self.active_filter = module
        for mod, btn in self.nav_buttons.items():
            if mod == module:
                btn.configure(fg_color=COLOR_ACCENT_BLUE)
            else:
                btn.configure(fg_color="transparent")

        if module == ModuleType.RAM_MONITOR:
            self._refresh_ram_data_async(render_when_done=True)
        else:
            self._render_results_list()

    def _get_filtered_items(self) -> list[ScanItem]:
        if self.active_filter == ModuleType.ALL:
            return self.all_items
        return [i for i in self.all_items if i.module == self.active_filter]

    def _render_empty_state(self, message: str) -> None:
        for widget in self.results_scroll.winfo_children():
            widget.destroy()

        empty_lbl = ctk.CTkLabel(
            self.results_scroll,
            text=message,
            font=ctk.CTkFont(family=FONT_TEXT, size=14),
            text_color=COLOR_TEXT_SECONDARY,
            justify="center",
        )
        empty_lbl.pack(pady=110, padx=20)

    def _render_results_list(self) -> None:
        for widget in self.results_scroll.winfo_children():
            widget.destroy()

        # Special Dedicated View for Module 6: Monitor y Turbo RAM (Windows)
        if self.active_filter == ModuleType.RAM_MONITOR:
            self._render_ram_monitor_view()
            return

        filtered = self._get_filtered_items()
        self.count_label.configure(text=f"{len(filtered)} elemento(s) mostrados")

        if self.active_filter == ModuleType.DOWNLOADS_TM:
            self._render_tm_info_banner(self.results_scroll)
        elif self.active_filter == ModuleType.OPTIMIZATION:
            self._render_optimization_banner(self.results_scroll)

        if not filtered:
            self._render_empty_state(
                "No se encontraron elementos pendientes en este módulo."
            )
            return

        display_items = filtered[:200]
        for item in display_items:
            self._create_item_row(self.results_scroll, item)

        if len(filtered) > 200:
            more_lbl = ctk.CTkLabel(
                self.results_scroll,
                text=f"Mostrando los 200 elementos más pesados de {len(filtered)} encontrados.",
                font=ctk.CTkFont(family=FONT_TEXT, size=12),
                text_color=COLOR_TEXT_SECONDARY,
            )
            more_lbl.pack(pady=10)

    # -------------------------------------------------------------------------
    # Module 6: Live RAM Monitor & Turbo Boost View (Windows PC)
    # -------------------------------------------------------------------------
    def _render_ram_monitor_view(self) -> None:
        self.count_label.configure(text=f"{len(self.ram_groups)} grupos de procesos en RAM")

        health = self.ram_health or RamOptimizer.get_ram_health()
        if health.status_color == "green":
            accent = COLOR_SUCCESS_GREEN
            bg_tint = "#182D22"
        elif health.status_color == "amber":
            accent = COLOR_WARNING_AMBER
            bg_tint = "#332512"
        else:
            accent = COLOR_DANGER_RED
            bg_tint = "#381B1A"

        # Top RAM Health & Turbo Boost Hero Card
        hero = ctk.CTkFrame(
            self.results_scroll,
            fg_color=bg_tint,
            corner_radius=12,
            border_width=1,
            border_color=accent,
        )
        hero.pack(fill="x", padx=8, pady=(6, 12))

        top_row = ctk.CTkFrame(hero, fg_color="transparent")
        top_row.pack(fill="x", padx=16, pady=(14, 6))

        left_info = ctk.CTkFrame(top_row, fg_color="transparent")
        left_info.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            left_info,
            text=f"MEMORIA RAM FÍSICA WINDOWS ({format_size(health.total_ram_bytes)})",
            font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        ).pack(fill="x")

        ctk.CTkLabel(
            left_info,
            text=health.status_badge,
            font=ctk.CTkFont(family=FONT_DISPLAY, size=20, weight="bold"),
            text_color=accent,
            anchor="w",
        ).pack(fill="x", pady=(2, 2))

        ctk.CTkLabel(
            left_info,
            text=health.explanation,
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            text_color=COLOR_TEXT_PRIMARY,
            justify="left",
            wraplength=500,
            anchor="w",
        ).pack(fill="x")

        # Right Action Buttons inside Hero
        btn_col = ctk.CTkFrame(top_row, fg_color="transparent")
        btn_col.pack(side="right", padx=(10, 0))

        ctk.CTkButton(
            btn_col,
            text="🚀 Activar Modo Turbo RAM",
            font=ctk.CTkFont(family=FONT_TEXT, size=13, weight="bold"),
            fg_color=COLOR_SUCCESS_GREEN,
            hover_color="#25A847",
            text_color="#0E1A12",
            width=215,
            height=38,
            corner_radius=8,
            command=self._run_turbo_ram_boost_async,
        ).pack(pady=(0, 6))

        ctk.CTkButton(
            btn_col,
            text="🔄 Actualizar Monitor",
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            fg_color="#2E343B",
            hover_color="#3B424B",
            text_color=COLOR_TEXT_PRIMARY,
            width=215,
            height=30,
            corner_radius=7,
            command=lambda: self._refresh_ram_data_async(render_when_done=True),
        ).pack()

        # Section subtitle
        ctk.CTkLabel(
            self.results_scroll,
            text=(
                "TOP PROGRAMAS Y PROCESOS EN TU RAM AHORA MISMO (Agrupados automáticamente):"
            ),
            font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        ).pack(fill="x", padx=12, pady=(4, 4))

        for grp in self.ram_groups:
            self._create_ram_group_row(self.results_scroll, grp)

    def _create_ram_group_row(self, parent: ctk.CTkScrollableFrame, grp: AppRamGroup) -> None:
        if grp.is_recyclable_daemon:
            border_col = "#244A32"
            pill_bg = "#1B3B28"
            pill_fg = COLOR_SUCCESS_GREEN
            pill_text = "🟢 Segundo Plano Reciclable (Seguro liberar)"
        elif grp.is_protected:
            border_col = COLOR_BORDER
            pill_bg = "#2C2C34"
            pill_fg = COLOR_TEXT_SECONDARY
            pill_text = "🔒 Sistema Windows / Sesión Activa"
        else:
            border_col = "#3E3828"
            pill_bg = "#3A2810"
            pill_fg = COLOR_WARNING_AMBER
            pill_text = f"🟡 {grp.category}"

        card = ctk.CTkFrame(
            parent,
            fg_color=COLOR_BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=border_col,
        )
        card.pack(fill="x", padx=8, pady=4)
        card.grid_columnconfigure(0, weight=1)

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.grid(row=0, column=0, padx=14, pady=10, sticky="ew")

        top_line = ctk.CTkFrame(info_frame, fg_color="transparent")
        top_line.pack(fill="x", anchor="w")

        ctk.CTkLabel(
            top_line,
            text=grp.app_name,
            font=ctk.CTkFont(family=FONT_TEXT, size=14, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(side="left")

        proc_label = (
            f"  {grp.process_count} procesos agrupados  "
            if grp.process_count > 1
            else "  1 proceso  "
        )
        ctk.CTkLabel(
            top_line,
            text=proc_label,
            font=ctk.CTkFont(family=FONT_TEXT, size=11),
            fg_color="#32323A",
            text_color=COLOR_TEXT_SECONDARY,
            corner_radius=6,
        ).pack(side="left", padx=(8, 0))

        ctk.CTkLabel(
            top_line,
            text=f"  {pill_text}  ",
            font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
            fg_color=pill_bg,
            text_color=pill_fg,
            corner_radius=6,
        ).pack(side="left", padx=(6, 0))

        ctk.CTkLabel(
            info_frame,
            text=grp.description,
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            text_color="#D0D0D6",
            justify="left",
            wraplength=510,
            anchor="w",
        ).pack(fill="x", pady=(4, 0))

        right_frame = ctk.CTkFrame(card, fg_color="transparent")
        right_frame.grid(row=0, column=1, padx=(8, 14), pady=10, sticky="e")

        size_col = (
            COLOR_DANGER_RED
            if grp.total_rss_bytes >= 1024 ** 3
            else COLOR_WARNING_AMBER
            if grp.total_rss_bytes >= 250 * (1024 ** 2)
            else COLOR_TEXT_PRIMARY
        )
        ctk.CTkLabel(
            right_frame,
            text=format_size(grp.total_rss_bytes),
            font=ctk.CTkFont(family=FONT_DISPLAY, size=15, weight="bold"),
            text_color=size_col,
            width=95,
            anchor="e",
        ).pack(side="left", padx=(0, 12))

        if grp.is_recyclable_daemon and not grp.is_protected:
            ctk.CTkButton(
                right_frame,
                text="⚡ Liberar RAM",
                font=ctk.CTkFont(family=FONT_TEXT, size=12, weight="bold"),
                fg_color="#1F3D2B",
                hover_color="#28523A",
                text_color=COLOR_SUCCESS_GREEN,
                width=125,
                height=30,
                corner_radius=7,
                command=lambda g=grp: self._free_single_ram_group_async(g),
            ).pack(side="left")
        elif grp.is_protected:
            ctk.CTkLabel(
                right_frame,
                text="Protegido",
                font=ctk.CTkFont(family=FONT_TEXT, size=11),
                text_color=COLOR_TEXT_SECONDARY,
                width=125,
                anchor="center",
            ).pack(side="left")
        else:
            ctk.CTkButton(
                right_frame,
                text="Cerrar App",
                font=ctk.CTkFont(family=FONT_TEXT, size=12),
                fg_color="#3A2828",
                hover_color=COLOR_DANGER_RED,
                text_color=COLOR_TEXT_PRIMARY,
                width=125,
                height=30,
                corner_radius=7,
                command=lambda g=grp: self._free_single_ram_group_async(g),
            ).pack(side="left")

    def _free_single_ram_group_async(self, grp: AppRamGroup) -> None:
        self.status_label.configure(text=f"Liberando memoria RAM de «{grp.app_name}»...")

        def worker() -> None:
            _, _, msg = RamOptimizer.free_process_group(grp)
            health = RamOptimizer.get_ram_health()
            groups = RamOptimizer.get_top_ram_groups(limit=18)
            self.ui_queue.put(("RAM_DATA_READY", (health, groups, True, msg, None)))

        threading.Thread(target=worker, daemon=True).start()

    def _run_turbo_ram_boost_async(self) -> None:
        self.status_label.configure(
            text="🚀 Ejecutando Modo Turbo RAM: compactando Working Sets, reciclando procesos 2º plano y limpiando DNS..."
        )

        def worker() -> None:
            _, _, msg = RamOptimizer.run_turbo_ram_boost()
            health = RamOptimizer.get_ram_health()
            groups = RamOptimizer.get_top_ram_groups(limit=18)
            self.ui_queue.put(("RAM_DATA_READY", (health, groups, True, msg, None)))

        threading.Thread(target=worker, daemon=True).start()

    def _render_optimization_banner(self, parent: ctk.CTkScrollableFrame) -> None:
        banner = ctk.CTkFrame(
            parent,
            fg_color="#1B2A38",
            corner_radius=10,
            border_width=1,
            border_color=COLOR_ACCENT_BLUE,
        )
        banner.pack(fill="x", padx=8, pady=(6, 10))

        left = ctk.CTkFrame(banner, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True, padx=14, pady=10)

        ctk.CTkLabel(
            left,
            text="⚡ Optimización Rápida de Windows (Miniaturas Explorer, Working Sets y DNS)",
            font=ctk.CTkFont(family=FONT_TEXT, size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x")

        ctk.CTkLabel(
            left,
            text=(
                "Limpia la caché DNS local (`ipconfig /flushdns`), purga bases de datos de miniaturas antiguas "
                "(`thumbcache_*.db`) y compacta páginas inactivas en RAM (`EmptyWorkingSet`)."
            ),
            font=ctk.CTkFont(family=FONT_TEXT, size=11),
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            wraplength=520,
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        ctk.CTkButton(
            banner,
            text="⚡ Optimizar Explorer y DNS",
            font=ctk.CTkFont(family=FONT_TEXT, size=12, weight="bold"),
            fg_color=COLOR_ACCENT_BLUE,
            hover_color=COLOR_ACCENT_BLUE_HOVER,
            text_color="#FFFFFF",
            width=195,
            height=34,
            corner_radius=8,
            command=self._run_quick_optimizations_async,
        ).pack(side="right", padx=14, pady=10)

    def _run_quick_optimizations_async(self) -> None:
        self.status_label.configure(text="Ejecutando optimización de Explorer, Working Sets y caché DNS...")

        def worker() -> None:
            msg = run_quick_windows_optimizations()
            self.ui_queue.put(("QUICK_OPT_DONE", msg))

        threading.Thread(target=worker, daemon=True).start()

    def _render_tm_info_banner(self, parent: ctk.CTkScrollableFrame) -> None:
        snap_count = len(self.tm_snapshots)
        banner = ctk.CTkFrame(
            parent,
            fg_color="#1D283A",
            corner_radius=10,
            border_width=1,
            border_color=COLOR_ACCENT_BLUE,
        )
        banner.pack(fill="x", padx=8, pady=(6, 10))

        title_text = (
            f"Restauración del Sistema e Hibernación en C:: {snap_count} elemento(s) del sistema detectados"
        )
        ctk.CTkLabel(
            banner,
            text=title_text,
            font=ctk.CTkFont(family=FONT_TEXT, size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x", padx=14, pady=(10, 2))

        if snap_count > 0:
            snaps_str = ", ".join(self.tm_snapshots)
            detail = (
                f"Detectado en disco C:: {snaps_str}\n"
                "Windows gestiona automáticamente las copias sombra (VSS) y el archivo de hibernación (`hiberfil.sys`)."
            )
        else:
            detail = "No hay copias sombra ni archivos de restauración reteniendo espacio adicional en este momento."

        ctk.CTkLabel(
            banner,
            text=detail,
            font=ctk.CTkFont(family=FONT_TEXT, size=11),
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            wraplength=740,
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 10))

    def _create_item_row(self, parent: ctk.CTkScrollableFrame, item: ScanItem) -> None:
        if item.safety_level == SafetyLevel.INSTALLED_APP:
            border_col = "#7A2E2A"
            badge_bg = "#3D1C1A"
            badge_fg = "#FF8A80"
        elif item.safety_level == SafetyLevel.SAFE:
            border_col = "#244A32"
            badge_bg = "#1B3B28"
            badge_fg = COLOR_SUCCESS_GREEN
        else:
            border_col = COLOR_WARNING_AMBER
            badge_bg = "#3A2810"
            badge_fg = COLOR_WARNING_AMBER

        card = ctk.CTkFrame(
            parent,
            fg_color=COLOR_BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=border_col,
        )
        card.pack(fill="x", padx=8, pady=5)
        card.grid_columnconfigure(1, weight=1)

        var = self.checkbox_vars.get(item.id)
        if var is None:
            var = ctk.BooleanVar(value=item.selected)
            self.checkbox_vars[item.id] = var

        cb = ctk.CTkCheckBox(
            card,
            text="",
            variable=var,
            width=24,
            checkbox_width=20,
            checkbox_height=20,
            corner_radius=6,
            fg_color=COLOR_SUCCESS_GREEN if item.safety_level == SafetyLevel.SAFE else COLOR_ACCENT_BLUE,
            command=lambda i=item, v=var: self._on_item_toggled(i, v),
        )
        cb.grid(row=0, column=0, rowspan=3, padx=(14, 8), pady=12, sticky="ns")

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.grid(row=0, column=1, padx=4, pady=10, sticky="ew")

        top_line = ctk.CTkFrame(info_frame, fg_color="transparent")
        top_line.pack(fill="x", anchor="w")

        name_lbl = ctk.CTkLabel(
            top_line,
            text=item.name,
            font=ctk.CTkFont(family=FONT_TEXT, size=14, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        name_lbl.pack(side="left")

        safety_pill = ctk.CTkLabel(
            top_line,
            text=f"  {item.safety_badge}  ",
            font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
            fg_color=badge_bg,
            text_color=badge_fg,
            corner_radius=6,
        )
        safety_pill.pack(side="left", padx=(8, 0))

        if item.category_tag:
            tag_lbl = ctk.CTkLabel(
                top_line,
                text=f"  {item.category_tag}  ",
                font=ctk.CTkFont(family=FONT_TEXT, size=11),
                fg_color="#32323A",
                text_color=COLOR_TEXT_SECONDARY,
                corner_radius=6,
            )
            tag_lbl.pack(side="left", padx=(6, 0))

        path_lbl = ctk.CTkLabel(
            info_frame,
            text=item.abbreviated_path,
            font=ctk.CTkFont(family=FONT_MONO, size=11),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
        )
        path_lbl.pack(fill="x", pady=(2, 0))

        if item.description:
            desc_lbl = ctk.CTkLabel(
                info_frame,
                text=item.description,
                font=ctk.CTkFont(family=FONT_TEXT, size=12),
                text_color="#D0D0D6",
                justify="left",
                wraplength=460,
                anchor="w",
            )
            desc_lbl.pack(fill="x", pady=(3, 0))

        if item.warning_label:
            warn_color = (
                "#FF6961"
                if item.safety_level == SafetyLevel.INSTALLED_APP
                else COLOR_SUCCESS_GREEN
                if item.safety_level == SafetyLevel.SAFE
                else COLOR_WARNING_AMBER
            )
            warn_lbl = ctk.CTkLabel(
                info_frame,
                text=item.warning_label,
                font=ctk.CTkFont(family=FONT_TEXT, size=11, weight="bold"),
                text_color=warn_color,
                justify="left",
                wraplength=460,
                anchor="w",
            )
            warn_lbl.pack(fill="x", pady=(4, 0))

        right_frame = ctk.CTkFrame(card, fg_color="transparent")
        right_frame.grid(row=0, column=2, padx=(8, 14), pady=10, sticky="e")

        size_color = (
            COLOR_DANGER_RED
            if item.size_bytes >= 1024 ** 3
            else COLOR_WARNING_AMBER
            if item.size_bytes >= 250 * 1024 ** 2
            else COLOR_TEXT_PRIMARY
        )
        size_lbl = ctk.CTkLabel(
            right_frame,
            text=format_size(item.size_bytes),
            font=ctk.CTkFont(family=FONT_DISPLAY, size=15, weight="bold"),
            text_color=size_color,
            width=95,
            anchor="e",
        )
        size_lbl.pack(side="left", padx=(0, 12))

        explorer_btn = ctk.CTkButton(
            right_frame,
            text="Ver en Explorador",
            font=ctk.CTkFont(family=FONT_TEXT, size=12),
            fg_color="#32323A",
            hover_color="#42424E",
            text_color=COLOR_TEXT_PRIMARY,
            width=125,
            height=30,
            corner_radius=7,
            command=lambda p=item.path: reveal_in_explorer(p),
        )
        explorer_btn.pack(side="left")

    # -------------------------------------------------------------------------
    # Selection & Cleaning Actions
    # -------------------------------------------------------------------------
    def _on_item_toggled(self, item: ScanItem, var: ctk.BooleanVar) -> None:
        item.selected = bool(var.get())
        self._update_selected_summary()

    def _select_safe_items(self) -> None:
        for item in self.all_items:
            is_safe = item.safety_level == SafetyLevel.SAFE
            item.selected = is_safe
            if item.id in self.checkbox_vars:
                self.checkbox_vars[item.id].set(is_safe)
        self._update_selected_summary()

    def _deselect_all(self) -> None:
        for item in self.all_items:
            item.selected = False
            if item.id in self.checkbox_vars:
                self.checkbox_vars[item.id].set(False)
        self._update_selected_summary()

    def _set_trash_button_state(self, selected_count: int) -> None:
        if selected_count > 0 and not self.is_busy:
            self.trash_btn.configure(
                state="normal",
                fg_color=COLOR_DANGER_RED,
                text_color="#FFFFFF",
                text=f"🗑️ Mover a la Papelera ({selected_count})",
            )
        else:
            self.trash_btn.configure(
                state="disabled",
                fg_color=COLOR_DISABLED_BTN_BG,
                text_color_disabled=COLOR_DISABLED_BTN_TEXT,
                text="🗑️ Mover a la Papelera (0)",
            )

    def _update_selected_summary(self) -> None:
        selected_items = [i for i in self.all_items if i.selected]
        sel_bytes = sum(i.size_bytes for i in selected_items)
        self.selected_summary_label.configure(
            text=f"Marcado ahora: {format_size(sel_bytes)} ({len(selected_items)} elem.)"
        )
        self._set_trash_button_state(len(selected_items))

    def _prompt_clean_selected(self) -> None:
        if self.is_busy:
            return
        selected_items = [i for i in self.all_items if i.selected]
        if not selected_items:
            return

        sel_bytes = sum(i.size_bytes for i in selected_items)
        active_apps_selected = [
            i.name for i in selected_items if i.safety_level == SafetyLevel.INSTALLED_APP
        ]

        ConfirmTrashDialog(
            parent=self,
            items_count=len(selected_items),
            total_size_str=format_size(sel_bytes),
            active_apps_selected=active_apps_selected,
            on_confirm=lambda: self._start_clean_thread(selected_items),
        )

    def _start_clean_thread(self, selected_items: list[ScanItem]) -> None:
        self.is_busy = True
        self.scan_btn.configure(state="disabled")
        self.trash_btn.configure(
            state="disabled",
            fg_color=COLOR_DISABLED_BTN_BG,
            text="⏳ Moviendo a Papelera...",
        )
        self.select_safe_btn.configure(state="disabled")
        self.clear_sel_btn.configure(state="disabled")
        self.progress_bar.set(0.05)

        def worker() -> None:
            result = SafeCleaner.clean_items(
                selected_items,
                progress_callback=lambda msg, p: self.ui_queue.put(("PROGRESS", (msg, p))),
            )
            new_trash_bytes = get_windows_trash_size()
            self.ui_queue.put(("CLEAN_DONE", (result, new_trash_bytes)))

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _on_clean_complete(self, payload: tuple[CleanResult, int]) -> None:
        self.is_busy = False
        result, new_trash_bytes = payload
        self.scan_btn.configure(state="normal")

        removed_set = set(result.succeeded_ids)
        self.all_items = [i for i in self.all_items if i.id not in removed_set]
        for rem_id in removed_set:
            self.checkbox_vars.pop(rem_id, None)

        module_bytes: dict[ModuleType, int] = {
            ModuleType.CACHES_LOGS: 0,
            ModuleType.DEV_JUNK: 0,
            ModuleType.APP_REMNANTS: 0,
            ModuleType.DOWNLOADS_TM: 0,
            ModuleType.OPTIMIZATION: 0,
        }
        total_bytes = 0
        for item in self.all_items:
            total_bytes += item.size_bytes
            module_bytes[item.module] = module_bytes.get(item.module, 0) + item.size_bytes
        module_bytes[ModuleType.ALL] = total_bytes

        self.total_gb_label.configure(text=format_size(total_bytes))
        safe_total = sum(i.size_bytes for i in self.all_items if i.safety_level == SafetyLevel.SAFE)
        self.safe_reclaim_label.configure(text=f"🟢 100% Seguro limpiar: {format_size(safe_total)}")

        for mod, badge in self.nav_badges.items():
            if mod == ModuleType.RAM_MONITOR:
                continue
            badge.configure(text=format_size(module_bytes.get(mod, 0)))

        self._update_trash_card_ui(new_trash_bytes)

        if self.all_items:
            self.select_safe_btn.configure(state="normal")
            self.clear_sel_btn.configure(state="normal")

        self._update_selected_summary()
        self._render_results_list()

        freed_str = format_size(result.bytes_freed)
        skip_note = (
            f" ({result.errors_skipped} archivos en uso omitidos silenciosamente)"
            if result.errors_skipped > 0
            else ""
        )
        self.status_label.configure(
            text=(
                f"✓ {freed_str} enviados a la Papelera de reciclaje{skip_note}. "
                "Pulsa «Vaciar Papelera» en el panel izquierdo cuando quieras liberar el espacio en tu disco C:."
            )
        )
        self.progress_bar.set(1.0)
