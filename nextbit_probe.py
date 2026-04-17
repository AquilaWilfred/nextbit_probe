#!/usr/bin/env python3
"""
NextBit Probe — Unified Super Tool
Cross-platform hardware diagnostics + fleet asset tracking
Combines: Laptop Inspector v2.5 deep health checks + NextBit USB v2 fleet logic

Checks:
  01. System info (model, serial, OS, BIOS age)
  02. OEM license key match
  03. CPU throttle stress test
  04. RAM stability test
  05. Battery health (wear %, cycles, capacity)
  06. Disk SMART (power-on hours, wear, errors)
  07. GPU condition (driver age, crash events)
  08. Display info + dead pixel launcher
  09. Temperature
  10. Network (Wi-Fi, Ethernet, internet)
  11. Peripherals (webcam, BT, audio, USB)
  12. OS & security (activation, AV, FW, TPM)
  13. Startup / performance snapshot
  14. Event log errors
  15. Fleet: sign + send to NextBit server (HMAC)
  16. Fleet: offline cache + retry

Author: XcognVis / NextBit
"""

import os, sys, platform, subprocess, json, hmac, hashlib, uuid
import socket, struct, time, threading, math, random, re
from datetime import datetime, timezone

# ── Optional deps ─────────────────────────────────────────────────
try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import qrcode
    from PIL import Image
    import io
    import base64
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import requests; HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import tkinter as tk
    from tkinter import ttk, font as tkfont
    HAS_TK = True
except ImportError:
    HAS_TK = False

# ── Paths ──────────────────────────────────────────────────────────
# Base dir: normally the script location, but when bundled by PyInstaller
# the files are extracted to `sys._MEIPASS`. Use that when available.
BASE_DIR    = os.path.dirname(os.path.abspath(sys.argv[0]))
_MEIPASS_DIR = getattr(sys, "_MEIPASS", None)
ASSET_BASE  = _MEIPASS_DIR or BASE_DIR
CONFIG_PATH = os.path.join(BASE_DIR, ".nextbit", "config.json")
KEY_PATH    = os.path.join(BASE_DIR, "keys", "hmac.key")
NET_PATH    = os.path.join(BASE_DIR, "keys", "network.fp")
CACHE_DIR   = os.path.join(BASE_DIR, "cache")
INSTALL_LOG = os.path.join(BASE_DIR, ".nextbit", "installed.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
# Use ASSET_BASE so assets are found inside PyInstaller bundles (sys._MEIPASS)
LOGO_PATH   = os.path.join(ASSET_BASE, "assets", "images", "NextBit.png")

# ── OS Detection ───────────────────────────────────────────────────
def detect_os():
    s = platform.system().lower()
    if s == "windows": return "windows"
    if s == "darwin":  return "macos"
    if s == "linux":
        try:
            content = open("/etc/os-release").read().lower()
            for name in ("ubuntu","debian","fedora","centos","arch","kali","manjaro","rhel","opensuse","alpine"):
                if name in content: return name
        except: pass
        return "linux"
    if s == "freebsd": return "freebsd"
    return f"unknown:{s}"

OS_TYPE   = detect_os()
OS_FAMILY = (
    "windows" if "windows" in OS_TYPE else
    "macos"   if OS_TYPE == "macos"   else
    "bsd"     if OS_TYPE in ("freebsd","openbsd","netbsd") else
    "linux"
)
IS_WINDOWS = OS_FAMILY == "windows"
IS_LINUX   = OS_FAMILY == "linux"
IS_MACOS   = OS_FAMILY == "macos"

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def run(cmd, shell=False, timeout=12):
    try:
        r = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout)
        return r.stdout.decode(errors="replace").strip()
    except: return None

def run_silent(cmd, shell=False):
    try:
        subprocess.Popen(cmd, shell=shell, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        return True
    except: return False

def safe(fn, default="N/A"):
    try:
        r = fn()
        return r if r not in (None, "", []) else default
    except: return default

def rate(value, excellent, good, poor, lower_is_better=True):
    """Returns (label, hex_color)"""
    COLORS = {
        "EXCELLENT": "#00e676",
        "GOOD":      "#29b6f6",
        "POOR":      "#ffa726",
        "VERY POOR": "#ef5350",
        "N/A":       "#78909c",
    }
    try: v = float(value)
    except: return "N/A", COLORS["N/A"]
    if lower_is_better:
        if v <= excellent: label = "EXCELLENT"
        elif v <= good:    label = "GOOD"
        elif v <= poor:    label = "POOR"
        else:              label = "VERY POOR"
    else:
        if v >= excellent: label = "EXCELLENT"
        elif v >= good:    label = "GOOD"
        elif v >= poor:    label = "POOR"
        else:              label = "VERY POOR"
    return label, COLORS[label]

def get_machine_id():
    if IS_WINDOWS:
        return run('powershell -NoProfile -Command "(Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Cryptography).MachineGuid"', shell=True)
    if IS_LINUX:
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(path):
                return open(path, "r", encoding="utf-8", errors="ignore").read().strip()
        return None
    if IS_MACOS:
        out = run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]) or ""
        for line in out.splitlines():
            if "IOPlatformUUID" in line:
                parts = line.split('"')
                if len(parts) >= 4:
                    return parts[3].strip()
    return None


def get_network_mac_addresses():
    macs = []
    if HAS_PSUTIL:
        for iface, addr_list in psutil.net_if_addrs().items():
            for addr in addr_list:
                fam = getattr(addr, "family", None)
                if fam == getattr(socket, "AF_PACKET", object()) or fam == getattr(socket, "AF_LINK", object()):
                    mac = getattr(addr, "address", "").strip().upper()
                    if mac and mac != "00:00:00:00:00:00":
                        macs.append(mac)
    if not macs:
        if IS_WINDOWS:
            out = run("getmac /NH /FO CSV", shell=True) or ""
            for line in out.splitlines():
                cols = [c.strip().strip('"') for c in line.split(",")]
                if cols and re.match(r"^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$", cols[0], re.I):
                    macs.append(cols[0].replace("-", ":").upper())
        else:
            out = run(["ip", "link", "show"]) or run(["ifconfig", "-a"]) or ""
            for mac in re.findall(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", out):
                if mac != "00:00:00:00:00:00":
                    macs.append(mac.upper())
    return sorted(set(macs))


def make_qr_payload(label, values):
    data = {"type": label}
    for k, v in values.items():
        if v not in (None, "", "N/A"):
            data[k] = v
    return json.dumps(data, separators=(",",":"), sort_keys=True)


def make_qr_with_logo(payload, logo_path=None):
    """Generate QR code with logo embedded in center, return as base64 PNG."""
    if not HAS_QRCODE or not payload:
        return None
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H,
                           box_size=10, border=2)
        qr.add_data(payload)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
        
        # Embed logo if provided
        if logo_path and os.path.exists(logo_path):
            try:
                logo = Image.open(logo_path).convert('RGBA')
                qr_width, qr_height = qr_img.size
                logo_size = qr_width // 5
                logo = logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
                
                # Create white background for logo
                bg = Image.new('RGB', (logo_size + 20, logo_size + 20), 'white')
                bg.paste(logo, (10, 10), logo)
                
                # Paste logo in center
                offset_x = (qr_width - bg.width) // 2
                offset_y = (qr_height - bg.height) // 2
                qr_img.paste(bg, (offset_x, offset_y))
            except Exception:
                pass  # If logo embedding fails, return QR without logo
        
        # Convert to base64 PNG
        buf = io.BytesIO()
        qr_img.save(buf, format='PNG')
        buf.seek(0)
        b64_str = base64.b64encode(buf.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{b64_str}"
    except Exception as e:
        print(f"[QR DEBUG] Error generating QR: {e}")
        return None

# ══════════════════════════════════════════════════════════════════
# NETWORK LOCK (from NextBit USB v2)
# ══════════════════════════════════════════════════════════════════

def _get_gateway_ip():
    if IS_WINDOWS:
        out = run("route print 0.0.0.0", shell=True) or ""
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0":
                return parts[2]
    elif IS_MACOS:
        out = run(["netstat", "-nr"]) or ""
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == "default":
                return parts[1]
    else:
        out = run(["ip", "route", "show", "default"]) or ""
        for line in out.splitlines():
            parts = line.split()
            if "default" in parts:
                try:
                    idx = parts.index("via")
                    return parts[idx + 1]
                except: pass
    return None

def _get_gateway_mac(gw_ip):
    if not gw_ip: return None
    if IS_WINDOWS:
        run(f"ping -n 1 -w 1000 {gw_ip}", shell=True)
        out = run(f"arp -a {gw_ip}", shell=True) or ""
        for line in out.splitlines():
            if gw_ip in line:
                for p in line.split():
                    if "-" in p and len(p) == 17:
                        return p.upper().replace("-", ":")
    else:
        run(["ping", "-c", "1", "-W", "1", gw_ip])
        out = run(["arp", "-n", gw_ip]) or ""
        for line in out.splitlines():
            for p in line.split():
                if ":" in p and len(p) == 17:
                    return p.upper()
    return None

def _get_subnet():
    if IS_WINDOWS:
        out = run("ipconfig", shell=True) or ""
        ip = mask = None
        for line in out.splitlines():
            line = line.strip()
            if "IPv4 Address" in line: ip   = line.split(":")[-1].strip()
            if "Subnet Mask"  in line: mask = line.split(":")[-1].strip()
            if ip and mask: return mask
    else:
        out = run(["ip", "addr", "show"]) or ""
        for ip, prefix in re.findall(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', out):
            if not ip.startswith("127."):
                bits = int(prefix)
                return socket.inet_ntoa(struct.pack(">I", (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
    return None

def verify_network():
    if not os.path.exists(NET_PATH):
        return True  # No network lock configured — allow scan (standalone mode)
    try:
        stored      = json.load(open(NET_PATH))
        stored_hash = stored.get("hash")
    except: return False
    gw_ip  = _get_gateway_ip()
    gw_mac = _get_gateway_mac(gw_ip)
    subnet = _get_subnet()
    raw    = json.dumps({"gateway_ip": gw_ip, "gateway_mac": gw_mac, "subnet": subnet}, sort_keys=True)
    if hashlib.sha256(raw.encode()).hexdigest() == stored_hash:
        return True
    preview = stored.get("preview", {})
    if preview.get("gateway_ip") == gw_ip and preview.get("subnet") == subnet and gw_ip:
        return True
    return False

# ══════════════════════════════════════════════════════════════════
# SELF-INSTALL (from NextBit USB v2)
# ══════════════════════════════════════════════════════════════════

def is_installed():
    if not os.path.exists(INSTALL_LOG): return False
    try: return json.load(open(INSTALL_LOG)).get("installed", False)
    except: return False

def mark_installed():
    os.makedirs(os.path.dirname(INSTALL_LOG), exist_ok=True)
    json.dump({"installed": True, "timestamp": datetime.now(timezone.utc).isoformat(),
               "hostname": platform.node(), "os": OS_TYPE},
              open(INSTALL_LOG, "w"), indent=2)

def self_install():
    if is_installed(): return
    exe = os.path.basename(sys.argv[0])
    try:
        if IS_LINUX:
            rule = (
                'ACTION=="add", SUBSYSTEM=="block", ENV{ID_FS_LABEL}=="NEXTBIT", '
                'RUN+="/bin/bash -c \'sleep 2 && mount /dev/%k /mnt/nextbit_probe '
                '2>/dev/null; python3 /mnt/nextbit_probe/nextbit_probe.py &\'"'
            )
            os.makedirs("/mnt/nextbit_probe", exist_ok=True)
            with open("/tmp/nextbit.rules", "w") as f: f.write(rule + "\n")
            run(["sudo", "cp", "/tmp/nextbit.rules", "/etc/udev/rules.d/99-nextbit.rules"])
            run(["sudo", "udevadm", "control", "--reload-rules"])
        elif IS_WINDOWS:
            ps = f"""
$q = "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
$a = {{
    $d = $Event.SourceEventArgs.NewEvent.DriveName
    $l = (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$d'").VolumeName
    if ($l -eq "NEXTBIT") {{ Start-Process "python" -ArgumentList "$d\\{exe}" -WindowStyle Hidden }}
}}
Register-WMIEvent -Query $q -Action $a -SourceIdentifier "NextBitUSB" | Out-Null
"""
            ps_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "nextbit_install.ps1")
            open(ps_path, "w").write(ps)
            run(["powershell", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", ps_path])
    except: pass
    mark_installed()

# ══════════════════════════════════════════════════════════════════
# SECTION 1 — SYSTEM INFO
# ══════════════════════════════════════════════════════════════════

def collect_system():
    info = {}

    if IS_WINDOWS:
        info["manufacturer"] = safe(lambda: run("wmic computersystem get manufacturer", shell=True).split("\n")[1].strip())
        info["model"]        = safe(lambda: run("wmic computersystem get model",        shell=True).split("\n")[1].strip())
        info["serial"]       = safe(lambda: run("wmic bios get serialnumber",           shell=True).split("\n")[1].strip())
        info["bios_version"] = safe(lambda: run("wmic bios get smbiosbiosversion",      shell=True).split("\n")[1].strip())
        info["bios_date"]    = safe(lambda: run("powershell -Command (Get-CimInstance Win32_BIOS).ReleaseDate.ToString('yyyy-MM-dd')", shell=True))
        info["cpu"]          = safe(lambda: run("wmic cpu get name", shell=True).split("\n")[1].strip())
        info["cpu_cores"]    = safe(lambda: int(run("wmic cpu get numberofcores", shell=True).split("\n")[1].strip()))
        info["cpu_threads"]  = safe(lambda: int(run("wmic cpu get numberoflogicalprocessors", shell=True).split("\n")[1].strip()))
        info["cpu_mhz"]      = safe(lambda: int(run("wmic cpu get maxclockspeed", shell=True).split("\n")[1].strip()))
        info["ram_gb"]       = safe(lambda: round(int(run("wmic computersystem get totalphysicalmemory", shell=True).split("\n")[1].strip()) / 1e9, 1))
        info["os_name"]      = safe(lambda: run("wmic os get caption", shell=True).split("\n")[1].strip())
        info["os_build"]     = safe(lambda: run("wmic os get buildnumber", shell=True).split("\n")[1].strip())
        info["os_arch"]      = safe(lambda: run("wmic os get osarchitecture", shell=True).split("\n")[1].strip())
        info["install_date"] = safe(lambda: run("powershell -Command (Get-CimInstance Win32_OperatingSystem).InstallDate.ToString('yyyy-MM-dd')", shell=True))
        info["last_boot"]    = safe(lambda: run("powershell -Command (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm')", shell=True))
    elif IS_LINUX:
        info["manufacturer"] = safe(lambda: open("/sys/class/dmi/id/sys_vendor").read().strip())
        info["model"]        = safe(lambda: open("/sys/class/dmi/id/product_name").read().strip())
        info["serial"]       = safe(lambda: run(["sudo", "dmidecode", "-s", "system-serial-number"]) or open("/sys/class/dmi/id/product_serial").read().strip())
        info["bios_version"] = safe(lambda: open("/sys/class/dmi/id/bios_version").read().strip())
        info["bios_date"]    = safe(lambda: open("/sys/class/dmi/id/bios_date").read().strip())
        info["cpu"]          = safe(lambda: [l.split(":")[1].strip() for l in open("/proc/cpuinfo") if "model name" in l][0])
        info["cpu_cores"]    = safe(lambda: int(run(["nproc"])))
        info["cpu_threads"]  = safe(lambda: psutil.cpu_count(logical=True) if HAS_PSUTIL else "N/A")
        info["cpu_mhz"]      = safe(lambda: int(float([l.split(":")[1].strip() for l in open("/proc/cpuinfo") if "cpu MHz" in l][0])))
        info["ram_gb"]       = safe(lambda: round(int([l.split()[1] for l in open("/proc/meminfo") if "MemTotal" in l][0]) / 1e6, 1))
        info["os_name"]      = safe(lambda: run(["lsb_release", "-ds"]) or platform.version())
        info["os_build"]     = safe(lambda: platform.release())
        info["os_arch"]      = safe(lambda: platform.machine())
        info["install_date"] = "N/A"
        info["last_boot"]    = safe(lambda: run(["who", "-b"]))
    elif IS_MACOS:
        info["manufacturer"] = "Apple"
        info["model"]        = safe(lambda: run(["sysctl", "-n", "hw.model"]))
        info["serial"]       = safe(lambda: [l.split(":")[-1].strip() for l in (run(["ioreg", "-l"]) or "").split("\n") if "IOPlatformSerialNumber" in l][0])
        info["bios_version"] = "EFI/UEFI"
        info["bios_date"]    = "N/A"
        info["cpu"]          = safe(lambda: run(["sysctl", "-n", "machdep.cpu.brand_string"]))
        info["cpu_cores"]    = safe(lambda: int(run(["sysctl", "-n", "hw.physicalcpu"])))
        info["cpu_threads"]  = safe(lambda: int(run(["sysctl", "-n", "hw.logicalcpu"])))
        info["cpu_mhz"]      = safe(lambda: int(int(run(["sysctl", "-n", "hw.cpufrequency"]) or 0) / 1e6))
        info["ram_gb"]       = safe(lambda: round(int(run(["sysctl", "-n", "hw.memsize"])) / 1e9, 1))
        sp = run(["sw_vers"]) or ""
        info["os_name"]      = safe(lambda: [l.split(":")[-1].strip() for l in sp.split("\n") if "ProductName" in l][0])
        info["os_build"]     = safe(lambda: [l.split(":")[-1].strip() for l in sp.split("\n") if "BuildVersion" in l][0])
        info["os_arch"]      = safe(lambda: platform.machine())
        info["install_date"] = "N/A"
        info["last_boot"]    = safe(lambda: run(["last", "reboot"]))

    # psutil supplements
    if HAS_PSUTIL:
        if info.get("ram_gb") == "N/A":
            info["ram_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
        if info.get("cpu_cores") == "N/A":
            info["cpu_cores"] = psutil.cpu_count(logical=False)
        if info.get("cpu_threads") == "N/A":
            info["cpu_threads"] = psutil.cpu_count(logical=True)

    info["hostname"]   = platform.node()
    info["os_type"]    = OS_TYPE
    info["os_version"] = platform.version()
    info["python"]     = platform.python_version()
    info["mac_addrs"]  = get_network_mac_addresses()
    info["mac_addr"]   = info["mac_addrs"][0] if info["mac_addrs"] else safe(lambda: ":".join(('%012X' % uuid.getnode())[i:i+2] for i in range(0,12,2)))
    info["machine_id"] = safe(get_machine_id)

    qr_payload_main = make_qr_payload("serial_machine_id", {
        "serial": info.get("serial"),
        "machine_id": info.get("machine_id")
    })
    qr_payload_audit = make_qr_payload("serial_machine_id_mac", {
        "serial": info.get("serial"),
        "machine_id": info.get("machine_id"),
        "mac_addrs": info.get("mac_addrs")
    })
    qr_svg_main = make_qr_with_logo(qr_payload_main, LOGO_PATH)
    qr_svg_audit = make_qr_with_logo(qr_payload_audit, LOGO_PATH)
    if qr_svg_main:
        print(f"[QR] Generated main QR code ({len(qr_svg_main)} bytes)")
    if qr_svg_audit:
        print(f"[QR] Generated audit QR code ({len(qr_svg_audit)} bytes)")
    info["qr"] = {
        "serial_machine_id": qr_svg_main,
        "audit": qr_svg_audit
    }

    # BIOS age rating
    bios_age_years = "N/A"
    bios_age_rating = ("N/A", "#78909c")
    if info.get("bios_date") not in ("N/A", None):
        try:
            from datetime import date
            parts = re.findall(r'\d+', info["bios_date"])
            if len(parts) >= 3:
                # Handle MM/DD/YYYY (BIOS format on Linux) or YYYY-MM-DD
                if len(parts[0]) == 4:
                    bd = date(int(parts[0]), int(parts[1]), int(parts[2]))
                else:
                    bd = date(int(parts[2]), int(parts[0]), int(parts[1]))
                bios_age_years = round((date.today() - bd).days / 365.25, 1)
                bios_age_rating = rate(bios_age_years, 1, 2, 4, lower_is_better=True)
        except: pass
    info["bios_age_years"]  = bios_age_years
    info["bios_age_rating"] = bios_age_rating

    return info

# ══════════════════════════════════════════════════════════════════
# SECTION 2 — OEM LICENSE
# ══════════════════════════════════════════════════════════════════

def collect_oem():
    if not IS_WINDOWS:
        return {"oem_key": "N/A (Windows only)", "installed_last5": "N/A", "match": "N/A"}
    oem_key = safe(lambda: run(
        'powershell -Command (Get-CimInstance -Query "SELECT OA3xOriginalProductKey FROM SoftwareLicensingService").OA3xOriginalProductKey',
        shell=True))
    installed = safe(lambda: run(
        'powershell -Command (Get-CimInstance SoftwareLicensingProduct | Where-Object {$_.PartialProductKey -and $_.Name -like "*Windows*"} | Select-Object -First 1).PartialProductKey',
        shell=True))
    match = "N/A"
    if oem_key not in ("N/A", None, "") and installed not in ("N/A", None, ""):
        match = "MATCH" if oem_key.endswith(installed) else "MISMATCH"
    return {"oem_key": oem_key, "installed_last5": installed, "match": match}

# ══════════════════════════════════════════════════════════════════
# SECTION 3 — CPU THROTTLE TEST
# ══════════════════════════════════════════════════════════════════

def collect_cpu_throttle(duration=10):
    base_mhz = "N/A"
    stress_mhz = "N/A"
    max_mhz = "N/A"
    pct = "N/A"

    if IS_WINDOWS:
        base_mhz = safe(lambda: int(run("wmic cpu get currentclockspeed", shell=True).split("\n")[1].strip()))
        max_mhz  = safe(lambda: int(run("wmic cpu get maxclockspeed",     shell=True).split("\n")[1].strip()))
    elif IS_LINUX:
        base_mhz = safe(lambda: int(float([l.split(":")[1].strip() for l in open("/proc/cpuinfo") if "cpu MHz" in l][0])))
        # Try to get max from cpufreq
        max_mhz = safe(lambda: int(int(open("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").read().strip()) / 1000))
        if max_mhz == "N/A":
            max_mhz = base_mhz
    elif IS_MACOS:
        base_mhz = safe(lambda: int(int(run(["sysctl", "-n", "hw.cpufrequency"]) or 0) / 1e6))
        max_mhz  = safe(lambda: int(int(run(["sysctl", "-n", "hw.cpufrequency_max"]) or 0) / 1e6))

    if HAS_PSUTIL:
        freq = psutil.cpu_freq()
        if freq:
            if base_mhz == "N/A": base_mhz = int(freq.current)
            if max_mhz  == "N/A": max_mhz  = int(freq.max or freq.current)

    # Stress burst
    end_time = time.time() + duration
    while time.time() < end_time:
        for i in range(30000):
            _ = math.sqrt(12345.678 * (i + 1))

    if IS_WINDOWS:
        stress_mhz = safe(lambda: int(run("wmic cpu get currentclockspeed", shell=True).split("\n")[1].strip()))
    elif IS_LINUX:
        stress_mhz = safe(lambda: int(float([l.split(":")[1].strip() for l in open("/proc/cpuinfo") if "cpu MHz" in l][0])))
    elif IS_MACOS:
        if HAS_PSUTIL:
            freq = psutil.cpu_freq()
            stress_mhz = int(freq.current) if freq else "N/A"
    if stress_mhz == "N/A" and HAS_PSUTIL:
        freq = psutil.cpu_freq()
        stress_mhz = int(freq.current) if freq else "N/A"

    if stress_mhz not in ("N/A", None) and max_mhz not in ("N/A", None):
        try:
            pct = round((int(stress_mhz) / int(max_mhz)) * 100, 1)
        except: pass

    rating = rate(pct, 95, 85, 70, lower_is_better=False) if pct != "N/A" else ("N/A", "#78909c")
    return {
        "base_mhz": base_mhz, "stress_mhz": stress_mhz, "max_mhz": max_mhz,
        "pct": pct, "rating": rating,
        "warning": pct != "N/A" and float(pct) < 85
    }

# ══════════════════════════════════════════════════════════════════
# SECTION 4 — RAM STABILITY
# ══════════════════════════════════════════════════════════════════

def collect_ram_test():
    errors = 0
    block_mb = 256
    if HAS_PSUTIL:
        total_gb = psutil.virtual_memory().total / 1e9
        blocks = min(4, max(1, int(total_gb / 2)))
    else:
        blocks = 2

    for _ in range(blocks):
        try:
            size = block_mb * 1024 * 1024
            arr = bytearray(size)
            rng = random.Random(42)
            for i in range(0, size, 4096):
                arr[i] = rng.randint(0, 255)
            rng2 = random.Random(42)
            for i in range(0, size, 4096):
                expected = rng2.randint(0, 255)
                if arr[i] != expected:
                    errors += 1
                    break
            del arr
        except: errors += 1

    if errors == 0:
        rating = ("EXCELLENT", "#00e676")
        result = "PASS"
    else:
        rating = ("VERY POOR", "#ef5350")
        result = f"ERRORS ({errors})"

    return {"blocks": blocks, "block_mb": block_mb, "errors": errors,
            "result": result, "rating": rating}

# ══════════════════════════════════════════════════════════════════
# SECTION 5 — BATTERY HEALTH
# ══════════════════════════════════════════════════════════════════

def collect_battery():
    data = {
        "present": False, "percent": "N/A", "plugged_in": "N/A",
        "design_mwh": "N/A", "full_mwh": "N/A", "wear_pct": "N/A",
        "cycles": "N/A", "chemistry": "N/A", "status": "N/A",
        "rating": ("N/A", "#78909c"), "desc": ""
    }

    if HAS_PSUTIL:
        try:
            b = psutil.sensors_battery()
            if b:
                data["present"]   = True
                data["percent"]   = round(b.percent, 1)
                data["plugged_in"] = b.power_plugged
        except: pass

    if IS_WINDOWS:
        # powercfg battery report
        import tempfile
        tmp = os.path.join(tempfile.gettempdir(), f"nb_batt_{int(time.time())}.html")
        run(f"powercfg /batteryreport /output {tmp}", shell=True)
        time.sleep(0.8)
        if os.path.exists(tmp):
            try:
                html = open(tmp, encoding="utf-8", errors="replace").read()
                m = re.search(r'DESIGN CAPACITY[\s\S]*?(\d[\d,]+)\s*mWh', html)
                if m: data["design_mwh"] = int(m.group(1).replace(",",""))
                m = re.search(r'FULL CHARGE CAPACITY[\s\S]*?(\d[\d,]+)\s*mWh', html)
                if m: data["full_mwh"] = int(m.group(1).replace(",",""))
                m = re.search(r'CYCLE COUNT[\s\S]*?(\d+)', html)
                if m: data["cycles"] = int(m.group(1))
                if data["design_mwh"] != "N/A" and data["full_mwh"] != "N/A":
                    dc, fc = data["design_mwh"], data["full_mwh"]
                    data["wear_pct"] = round(max(0, (1 - fc/dc) * 100), 1)
                os.remove(tmp)
            except: pass

        chem_map = {3:"Lead Acid",4:"NiCd",5:"NiMH",6:"Li-ion",7:"Zinc air",8:"Li-Polymer"}
        data["chemistry"] = safe(lambda: chem_map.get(int(run(
            "powershell -Command (Get-CimInstance Win32_Battery).Chemistry", shell=True)), "Unknown"))
        data["status"] = safe(lambda: run(
            "powershell -Command (Get-CimInstance Win32_Battery).Status", shell=True))

    elif IS_LINUX:
        base = "/sys/class/power_supply"
        try:
            for entry in os.listdir(base):
                ep = f"{base}/{entry}"
                cap_f = f"{ep}/capacity"
                if not os.path.exists(cap_f): continue
                data["present"] = True
                data["percent"] = int(open(cap_f).read().strip())
                status_f = f"{ep}/status"
                if os.path.exists(status_f):
                    st = open(status_f).read().strip()
                    data["plugged_in"] = st in ("Charging", "Full")
                    data["status"]     = st
                e_full_f = f"{ep}/energy_full"
                e_full_d = f"{ep}/energy_full_design"
                c_full_f = f"{ep}/charge_full"
                c_full_d = f"{ep}/charge_full_design"
                volt_f   = f"{ep}/voltage_now"
                if os.path.exists(e_full_f) and os.path.exists(e_full_d):
                    ef  = int(open(e_full_f).read().strip()) // 1000
                    efd = int(open(e_full_d).read().strip()) // 1000
                    data["full_mwh"]   = ef
                    data["design_mwh"] = efd
                    data["wear_pct"]   = round(max(0, (1 - ef/efd) * 100), 1) if efd > 0 else "N/A"
                elif os.path.exists(c_full_f) and os.path.exists(c_full_d) and os.path.exists(volt_f):
                    cf  = int(open(c_full_f).read().strip())
                    cfd = int(open(c_full_d).read().strip())
                    volt = int(open(volt_f).read().strip()) / 1e6
                    data["full_mwh"]   = round(cf * volt / 1e3)
                    data["design_mwh"] = round(cfd * volt / 1e3)
                    data["wear_pct"]   = round(max(0, (1 - cf/cfd) * 100), 1) if cfd > 0 else "N/A"
                cy_f = f"{ep}/cycle_count"
                if os.path.exists(cy_f):
                    data["cycles"] = int(open(cy_f).read().strip())
                break
        except: pass

    elif IS_MACOS and HAS_PSUTIL:
        pass  # psutil covers macOS battery basics

    # Rating
    wear = data["wear_pct"]
    cycles = data["cycles"]
    try: wear = float(wear)
    except: wear = 999
    try: cycles = int(cycles)
    except: cycles = 999

    if wear <= 10 and cycles < 300:
        data["rating"] = ("EXCELLENT", "#00e676")
        data["desc"]   = "Battery in excellent condition. Minimal wear."
    elif wear <= 25 and cycles < 500:
        data["rating"] = ("GOOD", "#29b6f6")
        data["desc"]   = "Battery in good condition. Normal wear for age."
    elif wear <= 40 and cycles < 800:
        data["rating"] = ("POOR", "#ffa726")
        data["desc"]   = "Significant wear. May need replacement soon."
    elif wear == 999 and not data["present"]:
        data["rating"] = ("N/A", "#78909c")
        data["desc"]   = "No battery detected (desktop or no sensor)."
    else:
        data["rating"] = ("VERY POOR", "#ef5350")
        data["desc"]   = "Battery heavily degraded. Replacement recommended."

    return data

# ══════════════════════════════════════════════════════════════════
# SECTION 6 — DISK SMART
# ══════════════════════════════════════════════════════════════════

def collect_disks():
    disks = []
    smart = {"power_on_hours": "N/A", "wear": "N/A", "read_errors": "N/A",
             "write_errors": "N/A", "reallocated": "N/A",
             "power_rating": ("N/A","#78909c"), "wear_rating": ("N/A","#78909c")}

    if HAS_PSUTIL:
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
                disks.append({
                    "device": p.device, "mountpoint": p.mountpoint,
                    "fstype": p.fstype,
                    "total_gb": round(u.total/1e9,1),
                    "used_gb":  round(u.used/1e9,1),
                    "free_gb":  round(u.free/1e9,1),
                    "used_pct": round(u.percent,1),
                })
            except: continue

    # SMART data
    if IS_WINDOWS:
        poh = safe(lambda: run("powershell -Command (Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object -First 1).PowerOnHours", shell=True))
        wear= safe(lambda: run("powershell -Command (Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object -First 1).Wear", shell=True))
        re_ = safe(lambda: run("powershell -Command (Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object -First 1).ReadErrorsTotal", shell=True))
        we_ = safe(lambda: run("powershell -Command (Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object -First 1).WriteErrorsTotal", shell=True))
        smart["power_on_hours"] = poh; smart["wear"] = wear
        smart["read_errors"] = re_; smart["write_errors"] = we_
    elif IS_LINUX:
        # Try smartctl
        sc = run(["sudo", "smartctl", "-A", "/dev/sda"])
        if sc:
            for line in sc.splitlines():
                if "Power_On_Hours" in line:
                    smart["power_on_hours"] = safe(lambda l=line: int(l.split()[-1]))
                if "Reallocated_Sector_Ct" in line:
                    smart["reallocated"] = safe(lambda l=line: int(l.split()[-1]))
                if "Reported_Uncorrect" in line or "Current_Pending_Sector" in line:
                    smart["read_errors"] = safe(lambda l=line: int(l.split()[-1]))
        # Try /sys for NVMe
        if smart["power_on_hours"] == "N/A":
            nvme_poh = run(["sudo", "smartctl", "-A", "/dev/nvme0"])
            if nvme_poh:
                for line in nvme_poh.splitlines():
                    if "Power On Hours" in line:
                        smart["power_on_hours"] = safe(lambda l=line: int(l.split(":")[-1].strip().replace(",","")))
    elif IS_MACOS:
        sc = run(["sudo", "smartctl", "-A", "/dev/disk0"])
        if sc:
            for line in sc.splitlines():
                if "Power_On_Hours" in line:
                    smart["power_on_hours"] = safe(lambda l=line: int(l.split()[-1]))

    if smart["power_on_hours"] not in ("N/A", None):
        smart["power_rating"] = rate(smart["power_on_hours"], 1000, 5000, 10000, lower_is_better=True)
    if smart["wear"] not in ("N/A", None):
        smart["wear_rating"] = rate(smart["wear"], 0, 5, 30, lower_is_better=True)
    elif smart["reallocated"] not in ("N/A", None):
        smart["wear_rating"] = rate(smart["reallocated"], 0, 5, 50, lower_is_better=True)

    return {"disks": disks, "smart": smart}

# ══════════════════════════════════════════════════════════════════
# SECTION 7 — GPU
# ══════════════════════════════════════════════════════════════════

def collect_gpu():
    gpus = []
    driver_date = "N/A"
    crashes = 0
    vram = "N/A"

    if IS_WINDOWS:
        names = safe(lambda: run("wmic path win32_videocontroller get name", shell=True))
        if names:
            gpus = [l.strip() for l in names.split("\n")[1:] if l.strip()]
        driver_date = safe(lambda: run("powershell -Command (Get-CimInstance Win32_VideoController | Select-Object -First 1).DriverDate.ToString('yyyy-MM-dd')", shell=True))
        vram_raw = safe(lambda: run("wmic path win32_videocontroller get adapterram", shell=True).split("\n")[1].strip())
        if vram_raw not in ("N/A", None, ""):
            try: vram = f"{round(int(vram_raw)/1e9,1)} GB"
            except: pass
        # Crash events (last 30 days)
        try:
            ev = run('powershell -Command "Get-WinEvent -FilterHashtable @{LogName=\'System\';Level=1,2,3;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {$_.Message -match \'display|nvlddmkm|atikmdag|igfx|gpu|dxgkrnl\'} | Measure-Object | Select-Object -ExpandProperty Count"', shell=True)
            if ev and ev.isdigit(): crashes = int(ev)
        except: pass
    elif IS_LINUX:
        lspci = run(["lspci"]) or ""
        gpus = [l for l in lspci.split("\n") if any(x in l for x in ("VGA","3D","Display","GPU"))]
        driver_ver = run(["glxinfo"]) or ""
        if not gpus:
            gpus = ["Intel Integrated (lspci unavailable)"]
    elif IS_MACOS:
        sp = run(["system_profiler", "SPDisplaysDataType"]) or ""
        gpus = [l.strip() for l in sp.split("\n") if "Chipset" in l or "GPU" in l]

    gpu_name = " / ".join(gpus) if gpus else "Unknown"
    is_dedicated = any(x in gpu_name.upper() for x in ("NVIDIA","AMD","RADEON","GEFORCE","RTX","GTX","QUADRO"))

    # Condition rating
    score = 0
    if driver_date not in ("N/A", None):
        try:
            from datetime import date
            parts = re.findall(r'\d+', driver_date)
            if len(parts) >= 3:
                dd = date(int(parts[0]), int(parts[1]), int(parts[2]))
                age_days = (date.today() - dd).days
                if age_days > 730:  score += 1
                if age_days > 1095: score += 1
        except: pass
    if crashes > 5: score += 2
    elif crashes > 0: score += 1

    if score <= 0:   gpu_rating = ("GOOD",       "#00e676"); gpu_desc = "GPU appears in good condition."
    elif score <= 2: gpu_rating = ("WARNING",     "#ffa726"); gpu_desc = "GPU shows some wear or outdated drivers."
    else:            gpu_rating = ("CONCERNING",  "#ef5350"); gpu_desc = "GPU may have been heavily used (mining/rendering)."

    return {
        "gpus": gpus, "gpu_name": gpu_name, "is_dedicated": is_dedicated,
        "driver_date": driver_date, "vram": vram, "crashes": crashes,
        "rating": gpu_rating, "desc": gpu_desc
    }

# ══════════════════════════════════════════════════════════════════
# SECTION 8 — DISPLAY
# ══════════════════════════════════════════════════════════════════

def collect_display():
    info = {"manufacturer": "N/A", "model": "N/A", "connection": "N/A",
            "resolution": "N/A", "refresh_hz": "N/A"}
    if IS_WINDOWS:
        info["manufacturer"] = safe(lambda: "".join(chr(c) for c in json.loads(
            run('powershell -Command "(Get-CimInstance -Namespace root\\wmi -ClassName WmiMonitorID | Select-Object -First 1).ManufacturerName | ConvertTo-Json"', shell=True) or "[]") if c > 0))
        info["model"] = safe(lambda: run(
            'powershell -Command "-join ((Get-CimInstance -Namespace root\\wmi -ClassName WmiMonitorID | Select-Object -First 1).UserFriendlyName | ForEach-Object {if($_ -gt 0){[char]$_}})"', shell=True))
        info["resolution"] = safe(lambda: run(
            'powershell -Command "$v=Get-CimInstance Win32_VideoController|Select-Object -First 1;\'$($v.CurrentHorizontalResolution) x $($v.CurrentVerticalResolution)\'"', shell=True))
        info["refresh_hz"] = safe(lambda: run(
            'powershell -Command "(Get-CimInstance Win32_VideoController|Select-Object -First 1).CurrentRefreshRate"', shell=True))
    elif IS_LINUX:
        xr = run(["xrandr", "--current"])
        if xr:
            for line in xr.split("\n"):
                if " connected" in line:
                    m = re.search(r'(\d+x\d+)\+', line)
                    if m: info["resolution"] = m.group(1)
                    info["model"] = line.split()[0]
    elif IS_MACOS:
        sp = run(["system_profiler", "SPDisplaysDataType"]) or ""
        for line in sp.split("\n"):
            if "Resolution" in line:
                info["resolution"] = line.split(":")[-1].strip()
    return info

# ══════════════════════════════════════════════════════════════════
# SECTION 9 — TEMPERATURE
# ══════════════════════════════════════════════════════════════════

def collect_temperature():
    temps = {}
    if HAS_PSUTIL:
        try:
            st = psutil.sensors_temperatures()
            for key, entries in st.items():
                for e in entries:
                    label = e.label or key
                    temps[label] = e.current
        except: pass
    if IS_WINDOWS and not temps:
        raw = safe(lambda: run(
            'powershell -Command "(Get-CimInstance -Namespace root\\WMI -ClassName MSAcpi_ThermalZoneTemperature | Select-Object -First 1).CurrentTemperature"', shell=True))
        if raw not in ("N/A", None):
            try: temps["CPU"] = round((int(raw)/10) - 273.15, 1)
            except: pass
    elif IS_LINUX and not temps:
        for f in ["/sys/class/thermal/thermal_zone0/temp", "/sys/class/hwmon/hwmon0/temp1_input"]:
            if os.path.exists(f):
                try: temps["CPU"] = round(int(open(f).read().strip()) / 1000, 1)
                except: pass

    if not temps:
        return {"temps": {}, "max_temp": "N/A", "rating": ("N/A","#78909c")}

    max_t = max(temps.values())
    return {"temps": temps, "max_temp": max_t,
            "rating": rate(max_t, 45, 65, 85, lower_is_better=True)}

# ══════════════════════════════════════════════════════════════════
# SECTION 10 — NETWORK
# ══════════════════════════════════════════════════════════════════

def collect_network():
    wifi_name = "N/A"; wifi_signal = "N/A"
    ethernet  = "N/A"; ifaces = []
    internet  = False; ping_ms = "N/A"

    if HAS_PSUTIL:
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        ifaces.append({"interface": name, "ip": addr.address, "netmask": addr.netmask})
        except: pass

    if IS_WINDOWS:
        wifi_name   = safe(lambda: [l.split(":")[-1].strip() for l in (run("netsh wlan show interfaces", shell=True) or "").split("\n") if "SSID" in l and "BSSID" not in l][0])
        wifi_signal = safe(lambda: [l.split(":")[-1].strip() for l in (run("netsh wlan show interfaces", shell=True) or "").split("\n") if "Signal" in l][0])
    elif IS_LINUX:
        wifi_name   = safe(lambda: run(["iwgetid", "-r"]))
        wifi_signal = safe(lambda: re.search(r'Signal level=(-\d+)', run(["iwconfig"]) or "").group(1) + " dBm")
    elif IS_MACOS:
        wifi_info = run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"])
        if wifi_info:
            for line in wifi_info.split("\n"):
                if " SSID:" in line: wifi_name   = line.split(":")[-1].strip()
                if "agrCtlRSSI" in line: wifi_signal = line.split(":")[-1].strip() + " dBm"

    # Internet check
    try:
        start = time.time()
        s = socket.create_connection(("8.8.8.8", 53), timeout=3)
        s.close()
        internet = True
        ping_ms  = round((time.time() - start) * 1000, 1)
    except: pass

    return {"wifi_name": wifi_name, "wifi_signal": wifi_signal,
            "ethernet": ethernet, "ifaces": ifaces,
            "internet": internet, "ping_ms": ping_ms,
            "mac": safe(lambda: ":".join(('%012X' % uuid.getnode())[i:i+2] for i in range(0,12,2)))}

# ══════════════════════════════════════════════════════════════════
# SECTION 11 — PERIPHERALS
# ══════════════════════════════════════════════════════════════════

def collect_peripherals():
    data = {"webcam":"N/A","bluetooth":"N/A","audio":"N/A",
            "keyboard":"N/A","touchpad":"N/A","usb_count":"N/A","fan":"N/A"}
    if IS_WINDOWS:
        data["webcam"]    = safe(lambda: run('powershell -Command "(Get-CimInstance Win32_PnPEntity | Where-Object {$_.PNPClass -eq \'Camera\'} | Select-Object -First 1).Name"', shell=True))
        data["bluetooth"] = safe(lambda: run('powershell -Command "(Get-CimInstance Win32_PnPEntity | Where-Object {$_.PNPClass -eq \'Bluetooth\'} | Select-Object -First 1).Name"', shell=True))
        data["audio"]     = safe(lambda: run('powershell -Command "(Get-CimInstance Win32_SoundDevice | Select-Object -First 1).Name"', shell=True))
        data["keyboard"]  = safe(lambda: run('powershell -Command "(Get-CimInstance Win32_Keyboard | Select-Object -First 1).Description"', shell=True))
        data["usb_count"] = safe(lambda: run('powershell -Command "(Get-CimInstance Win32_USBController | Measure-Object).Count"', shell=True))
    elif IS_LINUX:
        # lsusb for peripherals
        lsusb = run(["lsusb"]) or ""
        data["webcam"]    = "Detected" if any(x in lsusb.lower() for x in ("camera","webcam","video")) else "Not detected"
        data["bluetooth"] = "Detected" if "bluetooth" in lsusb.lower() or os.path.exists("/sys/class/bluetooth") else "Not detected"
        data["audio"]     = safe(lambda: run(["aplay", "-l"]))
        data["keyboard"]  = safe(lambda: run(["xinput", "--list"]))
        data["usb_count"] = len([l for l in lsusb.split("\n") if l.strip()])
        # Fan
        fan_files = []
        try:
            for root,dirs,files in os.walk("/sys/class/hwmon"):
                for f in files:
                    if f.startswith("fan") and f.endswith("_input"):
                        fan_files.append(os.path.join(root,f))
        except: pass
        if fan_files:
            try:
                rpm = int(open(fan_files[0]).read().strip())
                data["fan"] = f"{rpm} RPM"
            except: data["fan"] = "Detected (no RPM)"
        else:
            data["fan"] = "Not detected via sysfs"
    elif IS_MACOS:
        sp = run(["system_profiler", "SPUSBDataType"]) or ""
        data["webcam"]    = "Detected" if "camera" in sp.lower() or "facetime" in sp.lower() else "Check manually"
        data["bluetooth"] = safe(lambda: [l.strip() for l in (run(["system_profiler","SPBluetoothDataType"]) or "").split("\n") if "State" in l][0])
        data["usb_count"] = len(re.findall(r'Product ID:', sp))
    return data

# ══════════════════════════════════════════════════════════════════
# SECTION 12 — OS & SECURITY
# ══════════════════════════════════════════════════════════════════

def collect_security():
    data = {"activated":"N/A","antivirus":"N/A","firewall":"N/A",
            "tpm":"N/A","secure_boot":"N/A","bitlocker":"N/A"}
    if IS_WINDOWS:
        data["activated"]  = safe(lambda: "Activated" if "1" == run('powershell -Command "(Get-CimInstance SoftwareLicensingProduct | Where-Object {$_.PartialProductKey -and $_.Name -like \'*Windows*\'} | Select-Object -First 1).LicenseStatus"', shell=True) else "Not Activated")
        data["antivirus"]  = safe(lambda: "Defender Active" if "True" == run('powershell -Command "(Get-MpComputerStatus).RealTimeProtectionEnabled"', shell=True) else "Check manually")
        data["firewall"]   = safe(lambda: "Enabled" if run('powershell -Command "(Get-NetFirewallProfile | Where-Object {$_.Enabled}).Name"', shell=True) else "Disabled")
        data["tpm"]        = safe(lambda: run('powershell -Command "(Get-CimInstance -Namespace root\\cimv2\\security\\microsofttpm -ClassName Win32_Tpm).SpecVersion"', shell=True))
        data["secure_boot"]= safe(lambda: "Enabled" if "True" == run('powershell -Command "Confirm-SecureBootUEFI"', shell=True) else "Disabled")
        data["bitlocker"]  = safe(lambda: run('powershell -Command "(Get-BitLockerVolume -MountPoint C:).ProtectionStatus"', shell=True))
    elif IS_LINUX:
        data["firewall"]   = safe(lambda: "Active" if "active" in (run(["sudo","ufw","status"]) or "") else "Inactive (ufw)")
        data["secure_boot"]= safe(lambda: "Enabled" if "enabled" in (run(["mokutil","--sb-state"]) or "").lower() else "Disabled/N/A")
        data["tpm"]        = "Detected" if os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0") else "Not found"
        data["antivirus"]  = safe(lambda: "ClamAV" if run(["which","clamscan"]) else "None detected")
        data["firewall"]   = safe(lambda: "Active" if "active" in (run(["sudo","ufw","status"]) or "").lower() else
                             "Active" if "ACCEPT" in (run(["sudo","iptables","-L","-n"]) or "") else "Check manually")
    elif IS_MACOS:
        data["firewall"]   = safe(lambda: "Enabled" if "1" in (run(["defaults","read","/Library/Preferences/com.apple.alf","globalstate"]) or "") else "Disabled")
        data["tpm"]        = "Secure Enclave (T2/M-series)" if "Apple" in (run(["sysctl","-n","hw.model"]) or "") else "N/A"
        data["secure_boot"]= "Supported (check Security Utility)"
    return data

# ══════════════════════════════════════════════════════════════════
# SECTION 13 — PERFORMANCE SNAPSHOT
# ══════════════════════════════════════════════════════════════════

def collect_performance():
    data = {"process_count":"N/A","cpu_pct":"N/A","mem_pct":"N/A",
            "startup_count":"N/A","startup_rating":("N/A","#78909c"),
            "top_procs":[]}
    if HAS_PSUTIL:
        try:
            data["process_count"] = len(psutil.pids())
            data["cpu_pct"]       = psutil.cpu_percent(interval=1)
            data["mem_pct"]       = psutil.virtual_memory().percent
            procs = []
            for p in psutil.process_iter(["name","memory_info","pid"]):
                try: procs.append((p.info["name"], round(p.info["memory_info"].rss/1e6,1)))
                except: pass
            data["top_procs"] = sorted(procs, key=lambda x: x[1], reverse=True)[:5]
        except: pass
    if IS_WINDOWS:
        sc = safe(lambda: run('powershell -Command "(Get-CimInstance Win32_StartupCommand | Measure-Object).Count"', shell=True))
        try:
            data["startup_count"]  = int(sc)
            data["startup_rating"] = rate(int(sc), 10, 25, 50, lower_is_better=True)
        except: pass
    elif IS_LINUX:
        sc = safe(lambda: run(["systemctl","list-unit-files","--state=enabled","--no-pager"]))
        if sc:
            data["startup_count"]  = len([l for l in sc.split("\n") if "enabled" in l])
            data["startup_rating"] = rate(data["startup_count"], 20, 40, 80, lower_is_better=True)
    return data

# ══════════════════════════════════════════════════════════════════
# SECTION 14 — EVENT LOG ERRORS
# ══════════════════════════════════════════════════════════════════

def collect_events():
    count = 0
    events = []
    if IS_WINDOWS:
        out = safe(lambda: run(
            'powershell -Command "Get-WinEvent -FilterHashtable @{LogName=\'System\';Level=1,2;StartTime=(Get-Date).AddHours(-48)} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Json"',
            shell=True))
        if out and out != "N/A":
            try:
                evts = json.loads(out)
                if isinstance(evts, dict): evts = [evts]
                count  = len(evts)
                events = [{"time": e.get("TimeCreated",""), "id": e.get("Id",""), "msg": (e.get("Message","")[:120]+"...")} for e in evts[:5]]
            except: pass
    elif IS_LINUX:
        out = run(["journalctl","-p","err","-n","20","--no-pager","--since","48 hours ago"]) or ""
        events_raw = [l for l in out.split("\n") if l.strip()]
        count  = len(events_raw)
        events = [{"msg": l[:120]} for l in events_raw[:5]]
    elif IS_MACOS:
        out = run(["log","show","--predicate","messageType == 16","--last","48h","--info"]) or ""
        count = len([l for l in out.split("\n") if l.strip()])

    rating = rate(count, 0, 3, 10, lower_is_better=True)
    return {"count": count, "events": events, "rating": rating}

# ══════════════════════════════════════════════════════════════════
# FLEET: SIGN & SEND (from NextBit USB v2)
# ══════════════════════════════════════════════════════════════════

def fleet_sign(payload, key_bytes):
    body = json.dumps(payload, sort_keys=True, default=str).encode()
    return hmac.new(key_bytes, body, hashlib.sha256).hexdigest()

def fleet_send(payload, signature, server_url, usb_id):
    headers = {"X-NextBit-Signature": signature, "X-NextBit-USB": usb_id,
               "Content-Type": "application/json"}
    if HAS_REQUESTS:
        try:
            r = requests.post(server_url, json=payload, headers=headers, timeout=10)
            r.raise_for_status()
            return True, "sent"
        except: pass
    # Cache offline
    os.makedirs(CACHE_DIR, exist_ok=True)
    fname = datetime.now(timezone.utc).isoformat().replace(":","-") + ".json"
    json.dump({"payload": payload, "signature": signature},
              open(os.path.join(CACHE_DIR, fname), "w"), indent=2, default=str)
    return False, "cached"

def fleet_retry(server_url, usb_id):
    if not os.path.exists(CACHE_DIR) or not HAS_REQUESTS: return
    for fname in os.listdir(CACHE_DIR):
        if not fname.endswith(".json"): continue
        fpath = os.path.join(CACHE_DIR, fname)
        try:
            cached = json.load(open(fpath))
            r = requests.post(server_url, json=cached["payload"],
                              headers={"X-NextBit-Signature": cached["signature"],
                                       "X-NextBit-USB": usb_id,
                                       "Content-Type": "application/json"},
                              timeout=10)
            r.raise_for_status()
            os.remove(fpath)
        except: continue

# ══════════════════════════════════════════════════════════════════
# SCORING ENGINE
# ══════════════════════════════════════════════════════════════════

def compute_score(results):
    checks = []

    def add(name, passed, detail, weight=1):
        checks.append({"name": name, "passed": passed, "detail": detail, "weight": weight})

    s   = results.get("system", {})
    oem = results.get("oem", {})
    cpu = results.get("cpu_throttle", {})
    ram = results.get("ram_test", {})
    bat = results.get("battery", {})
    dsk = results.get("disks", {})
    gpu = results.get("gpu", {})
    tmp = results.get("temperature", {})
    net = results.get("network", {})
    per = results.get("peripherals", {})
    sec = results.get("security", {})
    perf= results.get("performance", {})
    evt = results.get("events", {})

    # BIOS age
    by = s.get("bios_age_years", "N/A")
    add("BIOS Age", by == "N/A" or float(by) < 4 if by != "N/A" else True,
        f"{by} years", weight=1)

    # OEM key
    add("OEM Key Match", oem.get("match") in ("MATCH","N/A"),
        oem.get("match","N/A"), weight=2)

    # CPU throttle
    pct = cpu.get("pct","N/A")
    add("CPU Throttle", pct == "N/A" or float(pct) >= 70,
        f"Held {pct}% of max clock", weight=2)

    # RAM
    add("RAM Stability", ram.get("errors",0) == 0,
        ram.get("result","N/A"), weight=2)

    # Battery
    wear = bat.get("wear_pct","N/A")
    add("Battery Wear", wear == "N/A" or float(wear) < 30,
        f"Wear {wear}% | Cycles {bat.get('cycles','N/A')}", weight=3)

    # Disk SMART
    smart = dsk.get("smart",{})
    poh = smart.get("power_on_hours","N/A")
    add("Disk Power-On", poh == "N/A" or int(poh) < 10000,
        f"{poh} hours — {smart.get('power_rating',('N/A',''))[0]}", weight=3)
    w = smart.get("wear","N/A")
    add("Disk Wear", w == "N/A" or int(w) < 30,
        f"Wear {w} | Read err {smart.get('read_errors','N/A')}", weight=3)

    # GPU
    add("GPU Condition", gpu.get("rating",("N/A",""))[0] in ("GOOD","N/A"),
        f"{gpu.get('rating',('N/A',''))[0]} — Crashes {gpu.get('crashes',0)}", weight=2)

    # Temperature
    mt = tmp.get("max_temp","N/A")
    add("Temperature", mt == "N/A" or float(mt) < 85,
        f"{mt}°C — {tmp.get('rating',('N/A',''))[0]}", weight=1)

    # Network
    add("Internet",    net.get("internet", False),
        f"Ping {net.get('ping_ms','N/A')} ms", weight=1)

    # Security (Windows)
    add("OS Activation", sec.get("activated") in ("Activated","N/A"),
        sec.get("activated","N/A"), weight=2)
    add("Antivirus", sec.get("antivirus") not in ("None detected","N/A"),
        sec.get("antivirus","N/A"), weight=1)

    # Event log
    cnt = evt.get("count",0)
    add("System Errors (48h)", cnt == 0,
        f"{cnt} critical errors — {evt.get('rating',('N/A',''))[0]}", weight=2)

    total_w   = sum(c["weight"] for c in checks)
    earned_w  = sum(c["weight"] for c in checks if c["passed"])
    score_pct = round((earned_w / total_w) * 100) if total_w else 0

    if   score_pct >= 85: overall = ("EXCELLENT", "#00e676")
    elif score_pct >= 70: overall = ("GOOD",      "#29b6f6")
    elif score_pct >= 50: overall = ("POOR",       "#ffa726")
    else:                 overall = ("VERY POOR",  "#ef5350")

    return {"checks": checks, "earned": earned_w, "total": total_w,
            "pct": score_pct, "overall": overall}

# ══════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════

def _evt_table(evt):
    if not evt.get("events"):
        return ""
    rows = ""
    for e in evt["events"]:
        t = e.get("time", "")
        i = e.get("id", "")
        m = e.get("msg", "")
        rows += f"<tr><td style='font-size:11px;color:var(--muted)'>{t}</td><td>{i}</td><td>{m}</td></tr>\n"
    return "<br><table><tr><th>Time</th><th>ID</th><th>Message</th></tr>" + rows + "</table>"

def generate_html_report(results, score):
    ts = results.get("timestamp","")
    sys_i = results.get("system",{})
    bat   = results.get("battery",{})
    gpu   = results.get("gpu",{})
    dsk   = results.get("disks",{})
    cpu_t = results.get("cpu_throttle",{})
    ram_t = results.get("ram_test",{})
    net   = results.get("network",{})
    sec   = results.get("security",{})
    per   = results.get("peripherals",{})
    tmp   = results.get("temperature",{})
    evt   = results.get("events",{})
    oem   = results.get("oem",{})
    fleet = results.get("fleet",{})

    # Extract QR codes before f-string to avoid brace conflicts
    qr_img_main = sys_i.get("qr", {}).get("serial_machine_id") or ""
    qr_img_audit = sys_i.get("qr", {}).get("audit") or ""
    qr_payload_main = sys_i.get("qr", {}).get("serial_machine_id_payload") or ""
    qr_payload_audit = sys_i.get("qr", {}).get("audit_payload") or ""
    
    qr_main_html = f'<img src="{qr_img_main}" alt="QR Code" style="width:100%;height:auto;max-width:260px;margin:0 auto;display:block;" />' if qr_img_main else '<div style="color:var(--muted);font-size:12px">QR unavailable</div>'
    qr_audit_html = f'<img src="{qr_img_audit}" alt="QR Code" style="width:100%;height:auto;max-width:260px;margin:0 auto;display:block;" />' if qr_img_audit else '<div style="color:var(--muted);font-size:12px">QR unavailable</div>'

    overall_label, overall_color = score["overall"]
    batt_label, batt_color = bat.get("rating",("N/A","#78909c"))
    gpu_label,  gpu_color  = gpu.get("rating",("N/A","#78909c"))
    disk_label, disk_color = dsk.get("smart",{}).get("power_rating",("N/A","#78909c"))
    cpu_label,  cpu_color  = cpu_t.get("rating",("N/A","#78909c"))
    ram_label,  ram_color  = ram_t.get("rating",("N/A","#78909c"))

    passed = sum(1 for c in score["checks"] if c["passed"])
    failed = len(score["checks"]) - passed

    check_rows = ""
    for c in score["checks"]:
        icon  = "✔" if c["passed"] else "✘"
        color = "#00e676" if c["passed"] else "#ef5350"
        check_rows += f'<tr><td style="color:{color};font-weight:bold">{icon}</td><td>{c["name"]}</td><td>×{c["weight"]}</td><td>{c["detail"]}</td></tr>\n'

    disk_rows = ""
    for d in dsk.get("disks",[]):
        pct = d.get("used_pct",0)
        pct_color = "#ef5350" if pct > 90 else "#ffa726" if pct > 75 else "#00e676"
        disk_rows += f'<tr><td>{d.get("device","")}</td><td>{d.get("mountpoint","")}</td><td>{d.get("total_gb","")} GB</td><td>{d.get("free_gb","")} GB</td><td style="color:{pct_color}">{pct}%</td></tr>\n'

    temp_rows = ""
    for label, val in tmp.get("temps",{}).items():
        t_color = "#ef5350" if val > 85 else "#ffa726" if val > 65 else "#00e676"
        temp_rows += f'<tr><td>{label}</td><td style="color:{t_color}">{val}°C</td></tr>\n'

    batt_gauge = max(0, 100 - (float(bat.get("wear_pct",0)) if bat.get("wear_pct","N/A") != "N/A" else 0))
    fleet_status = fleet.get("status","offline")
    fleet_color  = "#00e676" if fleet_status == "sent" else "#ffa726"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextBit Probe Report — {ts}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;600;700&display=swap');
  :root {{
    --bg:     #080c14;
    --panel:  #0d1524;
    --border: rgba(0,212,180,0.12);
    --accent: #00d4b4;
    --accent2:#3b82f6;
    --text:   #e2e8f0;
    --muted:  #64748b;
    --good:   #00e676;
    --warn:   #ffa726;
    --bad:    #ef5350;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box }}
  body {{ background:var(--bg); color:var(--text); font-family:'DM Sans',sans-serif; padding:24px; min-height:100vh }}
  body::before {{ content:''; position:fixed; inset:0; background:radial-gradient(ellipse 80% 50% at 20% 20%, rgba(0,212,180,.04) 0%, transparent 60%), radial-gradient(ellipse 60% 40% at 80% 80%, rgba(59,130,246,.04) 0%, transparent 60%); pointer-events:none }}
  .wrap {{ max-width:1100px; margin:0 auto }}
  .header {{ text-align:center; padding:40px 0 32px }}
  .header h1 {{ font-family:'Space Mono',monospace; font-size:clamp(20px,4vw,32px); color:var(--accent); letter-spacing:3px; text-transform:uppercase }}
  .header p {{ color:var(--muted); margin-top:8px; font-size:13px }}
  .badge {{ display:inline-block; padding:6px 20px; border-radius:20px; font-family:'Space Mono',monospace; font-weight:700; font-size:13px; letter-spacing:1px }}
  .result-hero {{ background:linear-gradient(135deg, {overall_color}18, {overall_color}08); border:1px solid {overall_color}40; border-radius:16px; padding:28px; text-align:center; margin-bottom:24px }}
  .result-hero .score-big {{ font-family:'Space Mono',monospace; font-size:clamp(36px,6vw,64px); font-weight:700; color:{overall_color}; line-height:1 }}
  .result-hero .score-label {{ color:{overall_color}; font-size:18px; font-weight:600; margin-top:8px; text-transform:uppercase; letter-spacing:2px }}
  .score-bar-wrap {{ background:rgba(255,255,255,.06); border-radius:8px; height:10px; margin:16px auto; max-width:500px; overflow:hidden }}
  .score-bar {{ height:100%; border-radius:8px; background:{overall_color}; transition:width .6s ease }}
  .grid-4 {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px }}
  .grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px }}
  .grid-3 {{ display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-bottom:16px }}
  .stat-card {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; text-align:center }}
  .stat-card .num {{ font-family:'Space Mono',monospace; font-size:22px; font-weight:700; margin-bottom:4px }}
  .stat-card .lbl {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:1px }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:20px; margin-bottom:16px }}
  .card h3 {{ font-family:'Space Mono',monospace; font-size:11px; text-transform:uppercase; letter-spacing:2px; color:var(--accent); margin-bottom:16px; padding-bottom:10px; border-bottom:1px solid var(--border) }}
  .kv {{ display:flex; justify-content:space-between; align-items:baseline; padding:6px 0; border-bottom:1px solid rgba(255,255,255,.04) }}
  .kv:last-child {{ border-bottom:none }}
  .kv .k {{ color:var(--muted); font-size:12px }}
  .kv .v {{ font-size:13px; font-weight:600; text-align:right; max-width:65% }}
  .gauge-wrap {{ background:rgba(255,255,255,.06); border-radius:8px; height:14px; overflow:hidden; margin:10px 0 6px }}
  .gauge {{ height:100%; border-radius:8px }}
  table {{ width:100%; border-collapse:collapse; font-size:12px }}
  th {{ background:rgba(0,212,180,.08); color:var(--accent); padding:8px; text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:1px; font-family:'Space Mono',monospace }}
  td {{ padding:7px 8px; border-bottom:1px solid rgba(255,255,255,.04); }}
  tr:last-child td {{ border-bottom:none }}
  .qr-grid {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:16px; margin-top:16px }}
  .qr-box {{ background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:16px; text-align:center }}
  .qr-box img {{ width:100%; height:auto; max-width:260px; margin:0 auto; display:block }}
  .tag {{ display:inline-block; padding:2px 10px; border-radius:12px; font-size:10px; font-weight:700; font-family:'Space Mono',monospace }}
  .fleet-bar {{ background:linear-gradient(90deg,{fleet_color}18,transparent); border:1px solid {fleet_color}30; border-radius:10px; padding:14px 20px; margin-bottom:16px; display:flex; justify-content:space-between; align-items:center }}
  .footer {{ text-align:center; color:var(--muted); font-size:11px; margin-top:40px; font-family:'Space Mono',monospace }}
  @media(max-width:700px) {{ .grid-4,.grid-2,.grid-3{{ grid-template-columns:1fr }} }}
</style>
<script>
function copyToClipboard(text) {{
  navigator.clipboard.writeText(text).then(function() {{
    alert('QR data copied to clipboard!');
  }}, function(err) {{
    console.error('Could not copy text: ', err);
    // Fallback for older browsers
    var textArea = document.createElement("textarea");
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {{
      document.execCommand('copy');
      alert('QR data copied to clipboard!');
    }} catch (err) {{
      alert('Failed to copy QR data');
    }}
    document.body.removeChild(textArea);
  }});
}}

function shareQR(qrDataUrl) {{
  if (navigator.share) {{
    fetch(qrDataUrl)
      .then(res => res.blob())
      .then(blob => {{
        const file = new File([blob], 'qr-code.png', {{ type: 'image/png' }});
        navigator.share({{
          title: 'NextBit QR Code',
          text: 'Device identification QR code',
          files: [file]
        }});
      }})
      .catch(err => {{
        console.error('Error sharing:', err);
        alert('Sharing not supported or failed');
      }});
  }} else {{
    alert('Web Share API not supported in this browser');
  }}
}}
</script>
</head>
<body>
<div class="wrap">

<div class="header">
  <h1>⬡ NextBit Probe</h1>
  <p>Hardware Diagnostic Report &nbsp;·&nbsp; {ts} &nbsp;·&nbsp; {sys_i.get('hostname','')} &nbsp;·&nbsp; {OS_TYPE}</p>
</div>

<div class="result-hero">
  <div class="score-big">{score['pct']}%</div>
  <div class="score-label">{overall_label}</div>
  <div class="score-bar-wrap"><div class="score-bar" style="width:{score['pct']}%"></div></div>
  <p style="color:var(--muted);font-size:13px;margin-top:8px">Score: {score['earned']}/{score['total']} &nbsp;·&nbsp; {passed} passed &nbsp;·&nbsp; {failed} failed</p>
</div>

<div class="grid-4">
  <div class="stat-card"><div class="num" style="color:{batt_color}">{batt_label}</div><div class="lbl">Battery</div></div>
  <div class="stat-card"><div class="num" style="color:{gpu_color}">{gpu_label}</div><div class="lbl">GPU</div></div>
  <div class="stat-card"><div class="num" style="color:{disk_color}">{disk_label}</div><div class="lbl">Disk Hours</div></div>
  <div class="stat-card"><div class="num" style="color:{cpu_color}">{cpu_label}</div><div class="lbl">CPU Throttle</div></div>
</div>

<div class="fleet-bar">
  <span style="font-family:'Space Mono',monospace;font-size:12px;color:var(--muted)">FLEET STATUS</span>
  <span class="badge" style="background:{fleet_color}18;color:{fleet_color};border:1px solid {fleet_color}40">{"✓ DATA SENT TO SERVER" if fleet_status=="sent" else "⚡ CACHED — WILL SEND WHEN ONLINE" if fleet_status=="cached" else "○ STANDALONE MODE"}</span>
</div>

<div class="grid-2">
<div>
  <div class="card">
    <h3>System</h3>
    <div class="kv"><span class="k">Manufacturer / Model</span><span class="v">{sys_i.get('manufacturer','')} {sys_i.get('model','')}</span></div>
    <div class="kv"><span class="k">Serial Number</span><span class="v">{sys_i.get('serial','')}</span></div>
    <div class="kv"><span class="k">Machine ID</span><span class="v">{sys_i.get('machine_id','')}</span></div>
    <div class="kv"><span class="k">CPU</span><span class="v">{sys_i.get('cpu','')}</span></div>
    <div class="kv"><span class="k">Cores / Threads</span><span class="v">{sys_i.get('cpu_cores','')} / {sys_i.get('cpu_threads','')}</span></div>
    <div class="kv"><span class="k">RAM</span><span class="v">{sys_i.get('ram_gb','')} GB</span></div>
    <div class="kv"><span class="k">OS</span><span class="v">{sys_i.get('os_name','')} ({sys_i.get('os_arch','')})</span></div>
    <div class="kv"><span class="k">Build</span><span class="v">{sys_i.get('os_build','')}</span></div>
    <div class="kv"><span class="k">Hostname</span><span class="v">{sys_i.get('hostname','')}</span></div>
    <div class="kv"><span class="k">MAC Address</span><span class="v">{sys_i.get('mac_addr','')}</span></div>
    <div class="kv"><span class="k">MAC Addresses</span><span class="v">{', '.join(sys_i.get('mac_addrs',[]))}</span></div>
  </div>
  <div class="card">
    <h3>Audit QR Codes</h3>
    <div class="qr-grid">
      <div class="qr-box">
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px">Serial + Machine ID</div>
        {qr_main_html}
        <div style="margin-top:10px;text-align:center">
          <button onclick="copyToClipboard('{qr_payload_main}')" style="background:#00d4b4;color:#080c14;border:none;padding:4px 8px;border-radius:4px;font-size:11px;margin-right:4px;cursor:pointer;">Copy Data</button>
          <button onclick="shareQR('{qr_img_main}')" style="background:#3b82f6;color:#fff;border:none;padding:4px 8px;border-radius:4px;font-size:11px;cursor:pointer;">Share</button>
        </div>
      </div>
      <div class="qr-box">
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px">Serial + Machine ID + MACs</div>
        {qr_audit_html}
        <div style="margin-top:10px;text-align:center">
          <button onclick="copyToClipboard('{qr_payload_audit}')" style="background:#00d4b4;color:#080c14;border:none;padding:4px 8px;border-radius:4px;font-size:11px;margin-right:4px;cursor:pointer;">Copy Data</button>
          <button onclick="shareQR('{qr_img_audit}')" style="background:#3b82f6;color:#fff;border:none;padding:4px 8px;border-radius:4px;font-size:11px;cursor:pointer;">Share</button>
        </div>
      </div>
    </div>
  </div>
  <div class="card">
    <h3>BIOS &amp; Age</h3>
    <div class="kv"><span class="k">BIOS Date</span><span class="v">{sys_i.get('bios_date','')}</span></div>
    <div class="kv"><span class="k">BIOS Version</span><span class="v">{sys_i.get('bios_version','')}</span></div>
    <div class="kv"><span class="k">BIOS Age</span><span class="v" style="color:{sys_i.get('bios_age_rating',('','#78909c'))[1]}">{sys_i.get('bios_age_years','')} years — {sys_i.get('bios_age_rating',('N/A',''))[0]}</span></div>
    <div class="kv"><span class="k">OS Installed</span><span class="v">{sys_i.get('install_date','')}</span></div>
    <div class="kv"><span class="k">Last Boot</span><span class="v">{sys_i.get('last_boot','')}</span></div>
  </div>
</div>
<div>
  <div class="card">
    <h3>Battery Health</h3>
    <div style="text-align:center;margin:6px 0 12px">
      <span class="badge" style="background:{batt_color}18;color:{batt_color};border:1px solid {batt_color}40;font-size:15px">{batt_label}</span>
    </div>
    <p style="color:var(--muted);font-size:12px;text-align:center;margin-bottom:12px">{bat.get('desc','')}</p>
    <div class="gauge-wrap"><div class="gauge" style="width:{batt_gauge:.0f}%;background:{batt_color}"></div></div>
    <div class="kv"><span class="k">Charge</span><span class="v">{bat.get('percent','')}%</span></div>
    <div class="kv"><span class="k">Wear Level</span><span class="v">{bat.get('wear_pct','')}%</span></div>
    <div class="kv"><span class="k">Cycle Count</span><span class="v">{bat.get('cycles','')}</span></div>
    <div class="kv"><span class="k">Design Capacity</span><span class="v">{bat.get('design_mwh','')} mWh</span></div>
    <div class="kv"><span class="k">Full Charge Cap</span><span class="v">{bat.get('full_mwh','')} mWh</span></div>
    <div class="kv"><span class="k">Chemistry</span><span class="v">{bat.get('chemistry','')}</span></div>
    <div class="kv"><span class="k">Plugged In</span><span class="v">{bat.get('plugged_in','')}</span></div>
  </div>
  <div class="card">
    <h3>GPU Condition</h3>
    <div style="text-align:center;margin:6px 0 8px">
      <span class="badge" style="background:{gpu_color}18;color:{gpu_color};border:1px solid {gpu_color}40;font-size:14px">{gpu_label}</span>
    </div>
    <p style="color:var(--muted);font-size:12px;text-align:center;margin-bottom:10px">{gpu.get('desc','')}</p>
    <div class="kv"><span class="k">GPU</span><span class="v">{gpu.get('gpu_name','')[:60]}</span></div>
    <div class="kv"><span class="k">Type</span><span class="v">{"Dedicated" if gpu.get('is_dedicated') else "Integrated"}</span></div>
    <div class="kv"><span class="k">VRAM</span><span class="v">{gpu.get('vram','')}</span></div>
    <div class="kv"><span class="k">Driver Date</span><span class="v">{gpu.get('driver_date','')}</span></div>
    <div class="kv"><span class="k">Crashes (30d)</span><span class="v" style="color:{'#ef5350' if gpu.get('crashes',0)>3 else '#ffa726' if gpu.get('crashes',0)>0 else '#00e676'}">{gpu.get('crashes',0)}</span></div>
  </div>
</div>
</div>

<div class="grid-2">
<div class="card">
  <h3>CPU Throttle Test</h3>
  <div style="text-align:center;margin:6px 0 10px">
    <span class="badge" style="background:{cpu_color}18;color:{cpu_color};border:1px solid {cpu_color}40;font-size:14px">{cpu_label}</span>
  </div>
  <div class="kv"><span class="k">Base Clock</span><span class="v">{cpu_t.get('base_mhz','')} MHz</span></div>
  <div class="kv"><span class="k">Under Stress</span><span class="v">{cpu_t.get('stress_mhz','')} MHz</span></div>
  <div class="kv"><span class="k">Max Clock</span><span class="v">{cpu_t.get('max_mhz','')} MHz</span></div>
  <div class="kv"><span class="k">Maintained</span><span class="v" style="color:{cpu_color}">{cpu_t.get('pct','')}%</span></div>
  {'<p style="color:#ffa726;font-size:12px;margin-top:8px">⚠ CPU may have thermal issues — check paste / cooling</p>' if cpu_t.get('warning') else ''}
</div>
<div class="card">
  <h3>RAM Stability Test</h3>
  <div style="text-align:center;margin:6px 0 10px">
    <span class="badge" style="background:{ram_color}18;color:{ram_color};border:1px solid {ram_color}40;font-size:14px">{ram_label}</span>
  </div>
  <div class="kv"><span class="k">Result</span><span class="v" style="color:{ram_color}">{ram_t.get('result','')}</span></div>
  <div class="kv"><span class="k">Blocks Tested</span><span class="v">{ram_t.get('blocks','')} × {ram_t.get('block_mb','')} MB</span></div>
  <div class="kv"><span class="k">Errors Found</span><span class="v">{ram_t.get('errors',0)}</span></div>
</div>
</div>

<div class="card">
  <h3>Disk SMART Health</h3>
  <div class="grid-3" style="margin-bottom:16px">
    <div class="stat-card"><div class="num" style="color:{disk_color}">{disk_label}</div><div class="lbl">Power-On Hours</div></div>
    <div class="stat-card"><div class="num" style="color:{dsk.get('smart',{}).get('wear_rating',('N/A','#78909c'))[1]}">{dsk.get('smart',{}).get('wear_rating',('N/A',''))[0]}</div><div class="lbl">Disk Wear</div></div>
    <div class="stat-card"><div class="num" style="color:var(--muted)">{dsk.get('smart',{}).get('power_on_hours','N/A')}</div><div class="lbl">Hours on Clock</div></div>
  </div>
  <div class="kv"><span class="k">Power-On Hours</span><span class="v">{dsk.get('smart',{}).get('power_on_hours','N/A')} hrs</span></div>
  <div class="kv"><span class="k">Wear Level</span><span class="v">{dsk.get('smart',{}).get('wear','N/A')}</span></div>
  <div class="kv"><span class="k">Reallocated Sectors</span><span class="v">{dsk.get('smart',{}).get('reallocated','N/A')}</span></div>
  <div class="kv"><span class="k">Read Errors</span><span class="v">{dsk.get('smart',{}).get('read_errors','N/A')}</span></div>
  <div class="kv"><span class="k">Write Errors</span><span class="v">{dsk.get('smart',{}).get('write_errors','N/A')}</span></div>
  <br>
  <table><tr><th>Device</th><th>Mount</th><th>Total</th><th>Free</th><th>Used</th></tr>{disk_rows}</table>
  <p style="color:var(--muted);font-size:11px;margin-top:8px">&lt;1000h = Excellent · &lt;5000h = Good · &lt;10000h = Poor · &gt;10000h = Very Poor</p>
</div>

<div class="grid-2">
<div class="card">
  <h3>Temperature</h3>
  {"<table><tr><th>Sensor</th><th>Temp</th></tr>" + temp_rows + "</table>" if temp_rows else '<p style="color:var(--muted);font-size:12px">No temperature sensors accessible (may need sudo/admin)</p>'}
</div>
<div class="card">
  <h3>Network</h3>
  <div class="kv"><span class="k">Wi-Fi SSID</span><span class="v">{net.get('wifi_name','')}</span></div>
  <div class="kv"><span class="k">Signal</span><span class="v">{net.get('wifi_signal','')}</span></div>
  <div class="kv"><span class="k">MAC</span><span class="v">{net.get('mac','')}</span></div>
  <div class="kv"><span class="k">Internet</span><span class="v" style="color:{'#00e676' if net.get('internet') else '#ef5350'}">{"Connected" if net.get('internet') else "No connection"}</span></div>
  <div class="kv"><span class="k">Ping (8.8.8.8)</span><span class="v">{net.get('ping_ms','')} ms</span></div>
</div>
</div>

<div class="grid-2">
<div class="card">
  <h3>OS &amp; Security</h3>
  <div class="kv"><span class="k">Activation</span><span class="v" style="color:{'#00e676' if sec.get('activated')=='Activated' else '#ffa726'}">{sec.get('activated','')}</span></div>
  <div class="kv"><span class="k">Antivirus</span><span class="v">{sec.get('antivirus','')}</span></div>
  <div class="kv"><span class="k">Firewall</span><span class="v">{sec.get('firewall','')}</span></div>
  <div class="kv"><span class="k">TPM</span><span class="v">{sec.get('tpm','')}</span></div>
  <div class="kv"><span class="k">Secure Boot</span><span class="v">{sec.get('secure_boot','')}</span></div>
  <div class="kv"><span class="k">BitLocker</span><span class="v">{sec.get('bitlocker','')}</span></div>
</div>
<div class="card">
  <h3>Peripherals</h3>
  <div class="kv"><span class="k">Webcam</span><span class="v">{per.get('webcam','')}</span></div>
  <div class="kv"><span class="k">Bluetooth</span><span class="v">{per.get('bluetooth','')}</span></div>
  <div class="kv"><span class="k">Audio</span><span class="v">{str(per.get('audio',''))[:60]}</span></div>
  <div class="kv"><span class="k">Keyboard</span><span class="v">{str(per.get('keyboard',''))[:60]}</span></div>
  <div class="kv"><span class="k">USB Controllers</span><span class="v">{per.get('usb_count','')}</span></div>
  <div class="kv"><span class="k">Fan</span><span class="v">{per.get('fan','')}</span></div>
</div>
</div>

<div class="card">
  <h3>OEM License</h3>
  <div class="kv"><span class="k">OEM Key in BIOS</span><span class="v">{"Embedded" if oem.get("oem_key") not in ("N/A","Not embedded",None) else oem.get("oem_key","")}</span></div>
  <div class="kv"><span class="k">Installed Key (last 5)</span><span class="v">{oem.get('installed_last5','')}</span></div>
  <div class="kv"><span class="k">Match</span><span class="v" style="color:{'#00e676' if oem.get('match')=='MATCH' else '#ef5350' if oem.get('match')=='MISMATCH' else '#78909c'}">{oem.get('match','')}</span></div>
</div>

<div class="card">
  <h3>System Event Errors (48h)</h3>
  <div class="kv"><span class="k">Error Count</span><span class="v" style="color:{evt.get('rating',('','#78909c'))[1]}">{evt.get('count',0)} — {evt.get('rating',('N/A',''))[0]}</span></div>
  {_evt_table(evt)}
</div>

<div class="card">
  <h3>Check Results — Full Breakdown</h3>
  <table>
    <tr><th>Status</th><th>Check</th><th>Weight</th><th>Detail</th></tr>
    {check_rows}
  </table>
</div>

<div class="footer">
  <p>NextBit Probe · XcognVis · {ts}</p>
  <p style="margin-top:4px">USB: {results.get('fleet',{}).get('usb_id','standalone')} · Python {platform.python_version()} · {OS_TYPE}</p>
</div>

</div>
</body>
</html>"""
    return html

# ══════════════════════════════════════════════════════════════════
# GUI — TKINTER RESULTS WINDOW
# ══════════════════════════════════════════════════════════════════

def show_gui(results, score, report_path):
    if not HAS_TK:
        print("[GUI] tkinter not available — report saved to:", report_path)
        return
    # Guard GUI creation: some environments have tkinter installed but no display
    try:
        root = tk.Tk()
    except tk.TclError:
        print("No display available for tkinter — report saved to:", report_path)
        return
    root.title("NextBit Probe — Scan Results")
    root.geometry("900x700")
    root.configure(bg="#080c14")
    root.resizable(True, True)

    overall_label, overall_color = score["overall"]

    # ── Header ──
    hf = tk.Frame(root, bg="#0d1524", pady=16)
    hf.pack(fill="x", padx=0)
    tk.Label(hf, text="⬡  NEXTBIT PROBE", font=("Courier", 18, "bold"),
             fg="#00d4b4", bg="#0d1524").pack()
    tk.Label(hf, text=f"{results.get('system',{}).get('manufacturer','')} {results.get('system',{}).get('model','')}  ·  {results.get('timestamp','')}",
             font=("Courier", 9), fg="#64748b", bg="#0d1524").pack(pady=(2,0))

    # ── Score banner ──
    sf = tk.Frame(root, bg=_hex_darken(overall_color), pady=14)
    sf.pack(fill="x")
    tk.Label(sf, text=f"{overall_label}  —  {score['pct']}%  ({score['earned']}/{score['total']})",
             font=("Courier", 15, "bold"), fg=overall_color,
             bg=_hex_darken(overall_color)).pack()

    # ── Tabs ──
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=12, pady=10)

    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook", background="#080c14", borderwidth=0)
    style.configure("TNotebook.Tab", background="#0d1524", foreground="#64748b",
                    font=("Courier",9), padding=[10,5])
    style.map("TNotebook.Tab", background=[("selected","#0d1524")],
              foreground=[("selected","#00d4b4")])

    def make_scroll_tab(label):
        frame = tk.Frame(nb, bg="#080c14")
        nb.add(frame, text=label)
        canvas = tk.Canvas(frame, bg="#080c14", highlightthickness=0)
        sb = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg="#080c14")
        cw = canvas.create_window((0,0), window=inner, anchor="nw")
        
        def _cfg(e): 
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(cw, width=canvas.winfo_width())
        
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            return "break"
        
        def _on_linux_scroll_up(event):
            canvas.yview_scroll(-1, "units")
            return "break"
        
        def _on_linux_scroll_down(event):
            canvas.yview_scroll(1, "units")
            return "break"
        
        inner.bind("<Configure>", _cfg)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        canvas.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Button-4>", _on_linux_scroll_up)
        canvas.bind("<Button-5>", _on_linux_scroll_down)
        canvas.bind("<Enter>", lambda e: canvas.focus_set())
        
        return inner

    def add_section(parent, title):
        tk.Label(parent, text=f"  {title}", font=("Courier",10,"bold"),
                 fg="#00d4b4", bg="#080c14", anchor="w").pack(fill="x", pady=(14,4), padx=8)
        tk.Frame(parent, bg="#0d2035", height=1).pack(fill="x", padx=8, pady=(0,4))

    def add_kv(parent, key, val, val_color="#e2e8f0", i=0):
        bg = "#0d1524" if i%2==0 else "#080c14"
        row = tk.Frame(parent, bg=bg)
        row.pack(fill="x")
        tk.Label(row, text=f"  {key}", width=22, anchor="w",
                 font=("Courier",9), fg="#64748b", bg=bg).pack(side="left", padx=(6,0), pady=3)
        tk.Label(row, text=str(val), anchor="w",
                 font=("Courier",9), fg=val_color, bg=bg,
                 wraplength=550, justify="left").pack(side="left", padx=4, pady=3)

    # Tab 1: Overview / Checks
    t1 = make_scroll_tab("  CHECKS  ")
    add_section(t1, "CHECK RESULTS")
    for i, c in enumerate(score["checks"]):
        icon  = "✔" if c["passed"] else "✘"
        color = "#00e676" if c["passed"] else "#ef5350"
        add_kv(t1, f"{icon} {c['name']}", f"×{c['weight']}  {c['detail']}", color, i)

    # Tab 2: Hardware
    t2 = make_scroll_tab("  HARDWARE  ")
    sys_i = results.get("system",{})
    add_section(t2, "SYSTEM")
    kvs = [("Model", f"{sys_i.get('manufacturer','')} {sys_i.get('model','')}"),
           ("Serial", sys_i.get("serial","")), ("CPU", sys_i.get("cpu","")),
           ("Cores/Threads", f"{sys_i.get('cpu_cores','')} / {sys_i.get('cpu_threads','')}"),
           ("RAM", f"{sys_i.get('ram_gb','')} GB"), ("MAC", sys_i.get("mac_addr","")),
           ("BIOS", f"{sys_i.get('bios_date','')} — {sys_i.get('bios_age_years','')} yrs")]
    for i,(k,v) in enumerate(kvs): add_kv(t2, k, v, i=i)

    bat = results.get("battery",{})
    add_section(t2, "BATTERY")
    bl, bc = bat.get("rating",("N/A","#78909c"))
    for i,(k,v,c) in enumerate([
        ("Rating", bl, bc), ("Wear", f"{bat.get('wear_pct','')}%", "#e2e8f0"),
        ("Cycles", bat.get("cycles",""), "#e2e8f0"),
        ("Capacity", f"{bat.get('full_mwh','')} / {bat.get('design_mwh','')} mWh", "#e2e8f0"),
        ("Charge", f"{bat.get('percent','')}%", "#e2e8f0")]):
        add_kv(t2, k, v, c, i)

    gpu = results.get("gpu",{})
    add_section(t2, "GPU")
    gl, gc = gpu.get("rating",("N/A","#78909c"))
    for i,(k,v,c) in enumerate([
        ("Rating", gl, gc), ("Name", gpu.get("gpu_name",""), "#e2e8f0"),
        ("VRAM", gpu.get("vram",""), "#e2e8f0"),
        ("Driver Date", gpu.get("driver_date",""), "#e2e8f0"),
        ("Crashes 30d", gpu.get("crashes",0), "#ef5350" if gpu.get("crashes",0)>0 else "#00e676")]):
        add_kv(t2, k, v, c, i)

    dsk = results.get("disks",{})
    add_section(t2, "DISK SMART")
    smart = dsk.get("smart",{})
    pl, pc = smart.get("power_rating",("N/A","#78909c"))
    for i,(k,v,c) in enumerate([
        ("Power-On Hours", f"{smart.get('power_on_hours','N/A')} — {pl}", pc),
        ("Wear/Sectors",   smart.get("wear","N/A"), "#e2e8f0"),
        ("Read Errors",    smart.get("read_errors","N/A"), "#e2e8f0"),
        ("Write Errors",   smart.get("write_errors","N/A"), "#e2e8f0")]):
        add_kv(t2, k, v, c, i)
    add_section(t2, "DRIVES")
    for i, d in enumerate(dsk.get("disks",[])):
        add_kv(t2, d.get("device",""), f"{d.get('total_gb','')}GB total  |  {d.get('free_gb','')}GB free  |  {d.get('used_pct','')}% used  →  {d.get('mountpoint','')}", i=i)

    # Tab 3: OS / Network
    t3 = make_scroll_tab("  OS & NET  ")
    sec = results.get("security",{})
    add_section(t3, "OS & SECURITY")
    for i,(k,v) in enumerate([("OS", f"{sys_i.get('os_name','')} {sys_i.get('os_arch','')}"),
        ("Build", sys_i.get("os_build","")), ("Installed", sys_i.get("install_date","")),
        ("Last Boot", sys_i.get("last_boot","")), ("Activation", sec.get("activated","")),
        ("Antivirus", sec.get("antivirus","")), ("Firewall", sec.get("firewall","")),
        ("TPM", sec.get("tpm","")), ("Secure Boot", sec.get("secure_boot","")),
        ("BitLocker", sec.get("bitlocker",""))]):
        col = "#00e676" if "Activated" in str(v) or "Active" in str(v) or "Enabled" in str(v) else "#e2e8f0"
        add_kv(t3, k, v, col, i)

    net = results.get("network",{})
    add_section(t3, "NETWORK")
    for i,(k,v) in enumerate([("Wi-Fi", net.get("wifi_name","")),
        ("Signal", net.get("wifi_signal","")), ("MAC", net.get("mac","")),
        ("Internet", "Connected" if net.get("internet") else "No connection"),
        ("Ping", f"{net.get('ping_ms','')} ms")]):
        col = "#00e676" if v == "Connected" else "#ef5350" if v == "No connection" else "#e2e8f0"
        add_kv(t3, k, v, col, i)

    per = results.get("peripherals",{})
    add_section(t3, "PERIPHERALS")
    for i,(k,v) in enumerate([("Webcam", per.get("webcam","")),
        ("Bluetooth", per.get("bluetooth","")), ("Audio", str(per.get("audio",""))[:80]),
        ("Keyboard", str(per.get("keyboard",""))[:80]),
        ("USB Controllers", per.get("usb_count","")), ("Fan", per.get("fan",""))]):
        add_kv(t3, k, v, i=i)

    # ── Bottom bar ──
    bf = tk.Frame(root, bg="#0d1524", pady=10)
    bf.pack(fill="x", side="bottom")
    tk.Button(bf, text="OPEN HTML REPORT", font=("Courier",10,"bold"),
              bg="#00d4b4", fg="#080c14", relief="flat", padx=20, pady=6,
              cursor="hand2",
              command=lambda: _open_file(report_path)).pack(side="left", padx=16)
    tk.Button(bf, text="CLOSE", font=("Courier",10),
              bg="#0d1524", fg="#64748b", relief="flat", padx=20, pady=6,
              cursor="hand2", command=root.destroy).pack(side="right", padx=16)
    tk.Label(bf, text=f"Report: {os.path.basename(report_path)}",
             font=("Courier",9), fg="#64748b", bg="#0d1524").pack(side="left")

    root.mainloop()

def _hex_darken(hex_color, factor=0.08):
    try:
        h = hex_color.lstrip("#")
        r,g,b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
        return f"#{int(r*factor):02x}{int(g*factor):02x}{int(b*factor):02x}"
    except: return "#0d1524"

def _open_file(path):
    import webbrowser
    webbrowser.open(f"file://{os.path.abspath(path)}")

# ══════════════════════════════════════════════════════════════════
# CONSOLE PROGRESS PRINTER
# ══════════════════════════════════════════════════════════════════

_CYAN  = "\033[96m"
_GREEN = "\033[92m"
_YELL  = "\033[93m"
_RED   = "\033[91m"
_GRAY  = "\033[90m"
_BOLD  = "\033[1m"
_RST   = "\033[0m"

def step(n, total, label):
    pct = int(n/total*100)
    bar = "█" * (pct//5) + "░" * (20 - pct//5)
    print(f"\r{_CYAN}[{bar}] {pct:3d}%{_RST}  {label:<45}", end="", flush=True)

def done_line(): print()

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    print(f"\n{_BOLD}{_CYAN}")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   NEXTBIT PROBE  ·  Unified Super Tool       ║")
    print("  ║   XcognVis / NextBit Platform                ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(f"{_RST}")

    # ── Load fleet config if present ──────────────────────────────
    fleet_cfg  = None
    fleet_key  = None
    fleet_mode = False
    try:
        fleet_cfg = json.load(open(CONFIG_PATH))
        fleet_key = open(KEY_PATH, "rb").read()
        fleet_mode = True
        print(f"  {_GREEN}Fleet mode:{_RST} USB {fleet_cfg['usb_id']} → {fleet_cfg['server_url']}")
    except:
        print(f"  {_GRAY}Standalone mode (no .nextbit/config.json found){_RST}")

    # ── Network lock check ────────────────────────────────────────
    if fleet_mode and not verify_network():
        print(f"\n  {_RED}Network lock: NOT on registered store network. Exiting.{_RST}\n")
        sys.exit(0)
    elif fleet_mode:
        print(f"  {_GREEN}Network lock: PASS{_RST}")

    # ── Self-install ──────────────────────────────────────────────
    if fleet_mode:
        self_install()
        if fleet_key:
            fleet_retry(fleet_cfg["server_url"], fleet_cfg["usb_id"])

    TOTAL_STEPS = 14
    print()
    results = {}
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    results["timestamp"] = ts.replace("_"," ")

    step(1, TOTAL_STEPS, "Collecting system info...")
    results["system"] = collect_system()
    done_line()

    step(2, TOTAL_STEPS, "Checking OEM license key...")
    results["oem"] = collect_oem()
    done_line()

    step(3, TOTAL_STEPS, "CPU throttle stress test (10s)...")
    results["cpu_throttle"] = collect_cpu_throttle(duration=10)
    done_line()

    step(4, TOTAL_STEPS, "RAM stability test...")
    results["ram_test"] = collect_ram_test()
    done_line()

    step(5, TOTAL_STEPS, "Battery health analysis...")
    results["battery"] = collect_battery()
    done_line()

    step(6, TOTAL_STEPS, "Disk SMART data...")
    results["disks"] = collect_disks()
    done_line()

    step(7, TOTAL_STEPS, "GPU condition check...")
    results["gpu"] = collect_gpu()
    done_line()

    step(8, TOTAL_STEPS, "Display info...")
    results["display"] = collect_display()
    done_line()

    step(9, TOTAL_STEPS, "Temperature sensors...")
    results["temperature"] = collect_temperature()
    done_line()

    step(10, TOTAL_STEPS, "Network scan...")
    results["network"] = collect_network()
    done_line()

    step(11, TOTAL_STEPS, "Peripherals...")
    results["peripherals"] = collect_peripherals()
    done_line()

    step(12, TOTAL_STEPS, "OS & security audit...")
    results["security"] = collect_security()
    done_line()

    step(13, TOTAL_STEPS, "Performance snapshot...")
    results["performance"] = collect_performance()
    done_line()

    step(14, TOTAL_STEPS, "Event log scan...")
    results["events"] = collect_events()
    done_line()

    # ── Scoring ───────────────────────────────────────────────────
    score = compute_score(results)
    ol, oc = score["overall"]

    # ── Fleet: sign & send ────────────────────────────────────────
    fleet_status = "offline"
    if fleet_mode and fleet_key and fleet_cfg:
        payload = {**results, "usb_id": fleet_cfg["usb_id"], "score_pct": score["pct"],
                   "overall": ol, "os_type": OS_TYPE, "hostname": platform.node()}
        sig = fleet_sign(payload, fleet_key)
        ok, fleet_status = fleet_send(payload, sig, fleet_cfg["server_url"], fleet_cfg["usb_id"])
        results["fleet"] = {"usb_id": fleet_cfg["usb_id"], "status": fleet_status,
                            "server": fleet_cfg["server_url"]}
    else:
        results["fleet"] = {"usb_id": "standalone", "status": "offline"}

    # ── Save reports ──────────────────────────────────────────────
    os.makedirs(REPORTS_DIR, exist_ok=True)
    html_path = os.path.join(REPORTS_DIR, f"nextbit_report_{ts}.html")
    json_path = os.path.join(REPORTS_DIR, f"nextbit_data_{ts}.json")

    open(html_path, "w", encoding="utf-8").write(generate_html_report(results, score))
    json.dump(results, open(json_path, "w", encoding="utf-8"), indent=2, default=str)

    # ── Console summary ───────────────────────────────────────────
    color_map = {"EXCELLENT":_GREEN,"GOOD":_CYAN,"POOR":_YELL,"VERY POOR":_RED,"N/A":_GRAY}
    c = color_map.get(ol, _GRAY)
    print(f"\n{_BOLD}  ┌──────────────────────────────────────────────┐")
    print(f"  │  RESULT: {c}{ol:<14}{_RST}{_BOLD}  SCORE: {score['pct']}% ({score['earned']}/{score['total']})  │")
    print(f"  └──────────────────────────────────────────────┘{_RST}\n")

    for ch in score["checks"]:
        icon  = f"{_GREEN}✔{_RST}" if ch["passed"] else f"{_RED}✘{_RST}"
        w_col = _GRAY
        print(f"  {icon}  {ch['name']:<24}{w_col}×{ch['weight']}{_RST}  {ch['detail']}")

    print(f"\n  {_GRAY}Battery : {results['battery']['rating'][0]}  |  GPU : {results['gpu']['rating'][0]}  |  Fleet : {fleet_status}{_RST}")
    print(f"\n  {_CYAN}HTML report :{_RST} {html_path}")
    print(f"  {_CYAN}JSON data   :{_RST} {json_path}")

    # ── GUI ───────────────────────────────────────────────────────
    print(f"\n  Opening results window...")
    show_gui(results, score, html_path)


if __name__ == "__main__":
    main()
