@echo off
setlocal
cd /d "%~dp0"

echo [AERO PC] Preparando entorno de compilacion para AERO.exe...

if not exist ".venv" (
    python -m venv .venv
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet

echo [AERO PC] Empaquetando AERO.exe nativo para Windows (doble clic) con PyInstaller...
python -m PyInstaller --noconfirm --clean ^
    --windowed ^
    --onefile ^
    --uac-admin ^
    --optimize 2 ^
    --name "AERO" ^
    --collect-all customtkinter ^
    --hidden-import send2trash ^
    --hidden-import psutil ^
    --exclude-module unittest ^
    --exclude-module pydoc ^
    --exclude-module doctest ^
    --exclude-module sqlite3 ^
    --exclude-module email ^
    --exclude-module http ^
    main.py

if exist "dist\AERO.exe" (
    copy /Y "dist\AERO.exe" "AERO.exe" >nul
    echo [AERO PC] Listo! Ejecutable creado en: %cd%\AERO.exe y %cd%\dist\AERO.exe
)
