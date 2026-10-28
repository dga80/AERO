#!/usr/bin/env python3
"""Entry point for AERO PC: Windows NTFS System Data Analyzer, Safe Cleaner & Turbo RAM."""

import ctypes
import platform
import sys

from ui.app_window import AeroSystemCleanerApp


def main() -> None:
    if platform.system() != "Windows":
        print(
            "Aviso: AERO PC está diseñado específicamente para Windows (NTFS). "
            "Algunas rutas o utilidades nativas de Windows podrían no estar disponibles."
        )
    else:
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("com.aero.pc.systemcleaner")
        except Exception:
            pass

    app = AeroSystemCleanerApp()
    app.mainloop()


if __name__ == "__main__":
    sys.exit(main())
