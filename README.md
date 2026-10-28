# AERO PC — Analizador NTFS, Limpiador Seguro y Turbo RAM (Windows)

**AERO PC** es una aplicación de escritorio moderna para **Windows 10 / 11** construida en Python con **CustomTkinter**, diseñada para analizar y limpiar de forma segura el almacenamiento del sistema en discos **NTFS (`C:`)** y optimizar el uso de **Memoria RAM y Paginación (Swap)** en tiempo real.

---

## ✨ Características Principales

1. **Cálculo Físico Real en NTFS (`GetCompressedFileSizeW`)**:
   - A diferencia de otras herramientas que muestran el tamaño lógico inflado de discos virtuales dispersos (*sparse files* como `ext4.vhdx` de WSL2/Docker) o archivos en la nube de OneDrive sin descargar, **AERO PC** consulta directamente a la API nativa de Windows (`kernel32.GetCompressedFileSizeW`) e ignora enlaces simbólicos/puntos de unión NTFS (*reparse points*) para mostrar el espacio físico real ocupado en tu SSD.

2. **6 Módulos Especializados para Windows**:
   - **1. Cachés y Temporales**: Analiza `%TEMP%` (`AppData\Local\Temp`), `C:\Windows\Temp`, `CrashDumps`, `Windows Error Reporting (WER)`, cachés de Shaders de GPU (`D3DSCache`, `NVIDIA DXCache/GLCache`, `AMD DxCache`), descargas antiguas de `Windows Update` y cachés web temporales de Chrome, Edge, Brave, Discord, Spotify y VS Code sin borrar tus contraseñas ni sesiones.
   - **2. Desarrollo e IA**: Detecta y limpia cachés pesadas de `pip`, `uv`, `npm`, `pnpm`, `Yarn`, `NuGet (.NET)`, `HuggingFace (~/.cache/huggingface)`, `PyTorch`, `Playwright`, `Puppeteer`, `Gradle`, `Maven`, `Cargo`, `Flutter/Dart` y `Go`.
   - **3. Inspector Inteligente de Restos de Programas**: Cruza `AppData\Roaming`, `AppData\Local`, `AppData\LocalLow` (> 150 MB) y carpetas ocultas (`~/.vscode`, `~/.android`, `~/.ollama`, `~/.lmstudio`, `~/.cursor`) con el Registro de Windows (`Uninstall`), `Program Files` y `AppData\Local\Programs`, distinguiendo automáticamente entre:
     - 🟢 **Programa desinstalado (Resto huérfano — 100% Seguro borrar)**
     - 🔴 **Programa instalado actualmente en uso (Protegido / No borrar)**
   - **4. Descargas Pesadas y Restauración del Sistema**: Localiza archivos `> 250 MB` en `~/Downloads` (destacando instaladores `.exe`, `.msi`, `.iso`, `.zip`, `.rar`, `.7z`), detecta copias antiguas de `C:\Windows.old` e inspecciona copias sombra (`vssadmin`) y el archivo de hibernación (`hiberfil.sys`).
   - **5. Inicio y Optimización**: Inspecciona programas de inicio automático en el menú `Startup` de Windows, detecta actualizadores fantasma y permite limpiar la caché DNS (`ipconfig /flushdns`), regenerar miniaturas del Explorador (`thumbcache_*.db`) y compactar memoria.
   - **🚀 6. Monitor y Turbo RAM (Especial equipos 8 GB / 16 GB)**:
     - Semáforo en tiempo real de **Presión de Memoria RAM Física** y uso de **Archivo de Paginación (Swap en SSD)**.
     - Agrupador inteligente de procesos (suma todos los subprocesos de Chrome, Edge, WebView2, Antigravity, VS Code, etc. en una sola fila legible).
     - Botón **«🚀 Activar Modo Turbo RAM»** que recicla procesos en segundo plano que inflan la RAM (`Widgets.exe`, `SearchHost.exe`, `PhoneExperienceHost`, `GameBar`, actualizadores de Edge/Chrome/Adobe) y ejecuta `EmptyWorkingSet` (`psapi.dll`) para devolver páginas de memoria inactivas a Windows sin cerrar tus programas de trabajo.

3. **Seguridad Blindada para Windows**:
   - Todo borrado utiliza exclusivamente **`Send2Trash`** para enviar archivos a la **Papelera de reciclaje de Windows**.
   - Panel integrado de **🗑️ Papelera de reciclaje** en la barra lateral (usando `SHQueryRecycleBinW` y `SHEmptyRecycleBinW`) para inspeccionar o vaciar la Papelera con confirmación previa.
   - Botón **«Ver en Explorador»** (`explorer.exe /select,`) en cada elemento detectado.

---

## 🚀 Uso directo con Doble Clic (`AERO.exe`)

Haz doble clic directamente sobre **`AERO.exe`** en la carpeta del proyecto (o en `dist\AERO.exe`). No requiere abrir terminal ni tener consola visible.

---

## 🛠️ Ejecución desde Código Fuente o Recompilación

```powershell
# Ejecutar desde código fuente
.\.venv\Scripts\python.exe main.py

# Generar de nuevo el ejecutable AERO.exe
.\build_app.bat
```
