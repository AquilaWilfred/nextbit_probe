Windows executable build instructions

Version : 0.0.1

Author  : A. A. W 

Company : XCognVis.com

Prerequisites (on Windows):
- Python 3.8+ (same major version used by the project)
- pip
- PyInstaller

1. Create a virtual environment and activate it:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # PowerShell
# or
.\.venv\Scripts\activate.bat   # cmd.exe
```

2. Install project deps and PyInstaller:

```powershell
pip install -r requirements.txt
pip install pyinstaller
```

3. From the project root, run the build script (or run the pyinstaller command shown):

```powershell
# If using the provided script on Windows via Git Bash or WSL, ensure the separators
# in --add-data use ';'. Alternatively run the pyinstaller command directly in PowerShell:
pyinstaller --noconfirm --onedir --windowed --name NextBitSetup \
  --add-data "nextbit_probe.py;." \
  --add-data "assets;assets" \
  --add-data "setup_usb.py;." \
  setup_usb.py

4. To include the NextBit logo as the executable icon:

```powershell
# Generate icons from the provided PNG (or copy your own .ico):
python tools/make_icons.py assets\images\NextBit.png

# Then pass the generated icon to PyInstaller
pyinstaller --noconfirm --onefile --windowed --name NextBitSetup \
  --add-data "assets;assets" \
  --icon build\icons\NextBit.ico \
  setup_usb.py
```
```

4. After the build completes, the output will be in `dist/NextBitSetup`.

Notes and caveats:
- This creates a "one-folder" build (an exe plus supporting files). The script `setup_usb.py` expects companion files (like `nextbit_probe.py` and `assets`) to be present next to the executable; the `--add-data` flags include those into the bundle.
- If you prefer a single-file `.exe`, use `--onefile` but be aware that file paths and runtime extraction differ; additional code changes may be needed to locate bundled data under `sys._MEIPASS`.
- To set a custom icon, add `--icon path\to\icon.ico` to the pyinstaller command.

