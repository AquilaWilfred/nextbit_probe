#!/usr/bin/env bash
# Build Windows executable (run on Windows or in a Windows environment)
# Usage: run in project root: ./build_windows.sh

set -e

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "PyInstaller not found. Install with: pip install pyinstaller"
  exit 1
fi

# Build a one-folder Windows build including data files.
# On Windows, --add-data uses ';' as separator. Adjust paths if necessary.
pyinstaller \
  --noconfirm \
  --onedir \
  --windowed \
  --name NextBitSetup \
  --add-data "nextbit_probe.py;." \
  --add-data "assets;assets" \
  --add-data "setup_usb.py;." \
  setup_usb.py

echo "Build finished. See the 'dist/NextBitSetup' folder for the executable and bundled files."