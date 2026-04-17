#!/usr/bin/env python3
"""Generate .ico and .icns from PNG using Pillow.

Usage: python tools/make_icons.py assets/images/NextBit.png
Outputs: build/icons/NextBit.ico, build/icons/NextBit.icns
"""
import os, sys

try:
    from PIL import Image
except Exception as e:
    print("Pillow is required. Install with: pip install pillow")
    raise

def make_icons(src_png, out_dir="build/icons", name="NextBit"):
    os.makedirs(out_dir, exist_ok=True)
    img = Image.open(src_png).convert("RGBA")

    # Create ICO (multiple sizes)
    ico_path = os.path.join(out_dir, f"{name}.ico")
    try:
        sizes = [(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)]
        imgs = [img.resize(s, Image.LANCZOS) for s in sizes]
        imgs[0].save(ico_path, format="ICO", sizes=sizes)
        print("Wrote:", ico_path)
    except Exception as e:
        print("Failed to create ICO:", e)

    # Create ICNS (macOS) if supported
    icns_path = os.path.join(out_dir, f"{name}.icns")
    try:
        # Pillow supports ICNS save on some platforms
        img.save(icns_path, format="ICNS")
        print("Wrote:", icns_path)
    except Exception as e:
        print("Failed to create ICNS (this is non-fatal):", e)

    return ico_path, icns_path

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python tools/make_icons.py path/to/logo.png")
        sys.exit(2)
    src = sys.argv[1]
    if not os.path.exists(src):
        print("Source PNG not found:", src)
        sys.exit(2)
    make_icons(src)
