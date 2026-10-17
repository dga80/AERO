#!/usr/bin/env python3
"""Entry point for AERO: macOS System Data Analyzer & Safe Cleaner."""

import platform
import sys

from ui.app_window import AeroSystemCleanerApp


def main() -> None:
    if platform.system() != "Darwin":
        print(
            "Aviso: AERO está diseñado específicamente para macOS (Darwin). "
            "Algunas rutas o utilidades como 'tmutil' y 'open -R' podrían no estar disponibles."
        )

    app = AeroSystemCleanerApp()
    app.mainloop()


if __name__ == "__main__":
    sys.exit(main())
