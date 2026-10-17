# AERO macOS — Analizador APFS, Limpiador Seguro y Turbo RAM (M1)

**AERO** es una aplicación de escritorio moderna para **macOS** construida en Python con **CustomTkinter**, diseñada para analizar y limpiar de forma segura el almacenamiento de **«Datos del Sistema» (System Data)** en volúmenes APFS y optimizar el uso de **Memoria Unificada (RAM)** en equipos Apple Silicon (M1/M2/M3/M4).

---

## ✨ Características Principales

1. **Cálculo Físico Real en APFS (`st_blocks * 512`)**:
   - A diferencia de otras utilidades que muestran el tamaño lógico inflado de archivos dispersos (*sparse files* como `Docker.raw`), AERO calcula los bloques físicos reales ocupados en el disco SSD APFS y deduplica enlaces duros (`st_ino`), coincidiendo con **Ajustes del Sistema → General → Almacenamiento**.

2. **6 Módulos Especializados**:
   - **1. Cachés y Registros Seguros**: Analiza subcarpetas de `~/Library/Caches` y `~/Library/Logs` sin tocar jamás las carpetas raíz ni las cachés internas protegidas de Apple (`com.apple.*`, `PassKit`, `GeoServices`, `CloudKit`).
   - **2. Desarrollo e IA (`~/.cache`)**: Detecta y limpia cachés pesadas de `Xcode DerivedData`, `CoreSimulator`, `HuggingFace (~/.cache/huggingface)`, `uv (~/.cache/uv)`, `npm (~/.npm/_cacache)`, `pip`, `Gradle (~/.gradle)`, `Flutter/Dart (~/.pub-cache)`, `Maven (~/.m2)`, `Cargo` y `Homebrew`.
   - **3. Inspector Inteligente de Restos de Apps**: Cruza `~/Library/Application Support`, `~/Library/Containers` (> 200 MB) y carpetas ocultas (`~/.vscode`, `~/.android`, `~/.rvm`, `~/.ollama`) con `/Applications` y Spotlight (`mdfind`), distinguiendo automáticamente entre:
     - 🟢 **App desinstalada (Resto huérfano — 100% Seguro borrar)**
     - 🔴 **App instalada actualmente en uso (Protegida / No borrar)**
   - **4. Descargas Pesadas y Time Machine**: Localiza archivos `> 500 MB` en `~/Downloads` (destacando `.dmg`, `.pkg`, `.zip`, `.iso`) y detecta instantáneas locales ocultas con `tmutil listlocalsnapshots /`.
   - **5. Inicio y Optimización**: Detecta agentes de inicio huérfanos o rotos en `~/Library/LaunchAgents`, desactiva actualizadores fantasma en `launchctl` y permite regenerar la caché de miniaturas de QuickLook (`qlmanage -r cache`) y limpiar la caché DNS local (`dscacheutil -flushcache`).
   - **🚀 6. Monitor y Turbo RAM (Especial Apple Silicon 8 GB)**:
     - Semáforo en tiempo real de **Presión de Memoria Unificada** y uso de **Swap en SSD**.
     - Agrupador inteligente de procesos (suma todos los `Helper / Renderer` de Chrome, Antigravity, etc. en una sola fila legible).
     - Botón **«🚀 Activar Modo Turbo RAM»** para reciclar demonios en segundo plano que acumulan memoria (`mediaanalysisd`, `photoanalysisd`, `AppleSpell`, `Weather`, `Home`, demonios de Adobe, etc.) sin cerrar tus apps de trabajo.

3. **Seguridad Blindada para macOS**:
   - Todo borrado utiliza exclusivamente **`Send2Trash`** para enviar archivos a la Papelera del Mac.
   - Panel integrado de **🗑️ Papelera del Mac** en la barra lateral para inspeccionar o vaciar la Papelera con confirmación previa.
   - Botón **«Ver en Finder»** (`open -R`) en cada elemento detectado.

---

## 🚀 Ejecución desde Código Fuente

```bash
# 1. Clonar el repositorio
git clone https://github.com/dga80/AERO.git
cd AERO

# 2. Crear entorno virtual e instalar dependencias
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Ejecutar la aplicación
python3 main.py
```

---

## 📦 Crear el Ejecutable Nativo (`AERO.app`)

El proyecto incluye un script automatizado con **PyInstaller** para generar el paquete nativo `AERO.app` para macOS:

```bash
chmod +x build_app.sh
./build_app.sh
```

Una vez finalizado, encontrarás la aplicación lista para usar en `dist/AERO.app`:

```bash
open dist/AERO.app
```
