# NextBit Probe — Unified Super Tool

Version : 0.0.1 <br>
Author  : A. A. W <br>
Company : XCognVis.com 

Cross-platform hardware diagnostics + NextBit fleet asset tracking.
Combines the deep health checks of **Hardware Health** with the
fleet logic of **NextBit USB PROBE** — in pure Python.

---

## What it does

| # | Check | Depth |
|---|-------|-------|
| 1 | System info (model, serial, BIOS age) | All platforms |
| 2 | OEM Windows license key match | Windows |
| 3 | CPU throttle stress test (10s burst) | All platforms |
| 4 | RAM stability (write/read pattern) | All platforms |
| 5 | Battery wear %, cycles, capacity | Win/Linux/macOS |
| 6 | Disk SMART (power-on hours, wear, errors) | All platforms |
| 7 | GPU condition (driver age, crash events) | All platforms |
| 8 | Display info | All platforms |
| 9 | Temperature sensors | All platforms |
| 10 | Network (Wi-Fi SSID, signal, internet, ping) | All platforms |
| 11 | Peripherals (webcam, BT, audio, USB, fan) | All platforms |
| 12 | OS & security (AV, FW, TPM, Secure Boot) | All platforms |
| 13 | Performance snapshot (CPU%, RAM%, top procs) | All platforms |
| 14 | Event log errors (48h) | Win/Linux |
| 15 | Fleet: HMAC sign + send to NextBit server | Fleet mode |
| 16 | Fleet: offline cache + auto-retry | Fleet mode |

**Outputs:**
- Polished HTML report (`reports/nextbit_report_TIMESTAMP.html`)
- JSON data file (`reports/nextbit_data_TIMESTAMP.json`)
- Tkinter GUI results window (3-tab: Checks / Hardware / OS & Net)
- Console summary with color-coded pass/fail

---

## Quick Start

### Standalone (no server — just diagnostics)

```bash
pip install -r requirements.txt
python nextbit_probe.py
```

### Fleet mode (USB + server)

**Step 1 — Provision the USB (once, on your store network):**
```bash
python setup_usb.py
```

The setup script scans for USB flash drives only and guides you through selecting the correct target device.

If you are on a machine without a graphical display, use the terminal mode:
```bash
python setup_usb.py --list-drives
python setup_usb.py --usb-id NB-USB-001 --drive-path /media/user/USB
```

If you do not have a server URL yet, press Enter to leave it blank and provision the USB for standalone mode.

**Step 2 — Copy to USB (label it `NEXTBIT`):**
```
nextbit_probe.py
setup_usb.py
requirements.txt
README.md
.nextbit/config.json
keys/hmac.key
keys/network.fp
autorun.inf
```

**Step 3 — On Linux, first plug needs:**
```bash
sudo python nextbit_probe.py
```
After that, udev auto-runs it on every plug.

**Step 4 — Windows AutoPlay:**
Add `autorun.inf`:
```ini
[AutoRun]
open=python nextbit_probe.py
label=NEXTBIT Probe
```

---

## Scoring

| Score | Grade |
|-------|-------|
| ≥ 85% | EXCELLENT |
| ≥ 70% | GOOD |
| ≥ 50% | POOR |
| < 50% | VERY POOR |

Checks are weighted — Battery (×3), Disk (×3), OEM Key (×2),
CPU Throttle (×2), RAM (×2), Activation (×2), Events (×2),
GPU (×2), BIOS Age (×1), Temp (×1), Internet (×1), AV (×1).

---

## Fleet Security

- HMAC-SHA256 signs every payload (`keys/hmac.key`)
- Network lock (`keys/network.fp`) — USB exits silently if not on registered store network
- Server verifies `X-NextBit-Signature` header
- Offline scans cached on USB, retried automatically on next plug

---

## Platform Notes

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Battery wear/cycles | ✅ powercfg | ✅ /sys | ✅ psutil |
| SMART power-on hours | ✅ WMI | ✅ smartctl | ✅ smartctl |
| GPU crashes | ✅ Event log | — | — |
| OEM key check | ✅ WMI | — | — |
| Temperature | ✅ ACPI WMI | ✅ hwmon/psutil | ✅ psutil |
| Auto-run on plug | ✅ Task Sched | ✅ udev | ✅ LaunchDaemon |

---

## Dependencies

```
psutil     — CPU, RAM, disk, battery, network (required)
requests   — Fleet HTTP send (required for fleet mode)
tkinter    — GUI window (built into standard Python)
smartctl   — Deep disk SMART on Linux/macOS (sudo apt install smartmontools)
```
