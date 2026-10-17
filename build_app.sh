#!/usr/bin/env zsh
set -e

cd "$(dirname "$0")"

echo "🚀 Preparando entorno de compilación para AERO.app..."

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

echo "📦 Empaquetando AERO.app nativo para macOS con PyInstaller..."
pyinstaller --noconfirm --clean \
    --windowed \
    --onedir \
    --name "AERO" \
    --osx-bundle-identifier "com.aero.systemcleaner" \
    --collect-all customtkinter \
    --hidden-import send2trash \
    main.py

echo "✅ ¡Listo! Ejecutable creado en: $(pwd)/dist/AERO.app"
