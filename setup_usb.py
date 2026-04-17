#!/usr/bin/env python3
"""
NextBit Probe — USB Provisioning GUI
Auto-elevates to root on Linux/macOS. Just double-click or run normally.

Requires: tkinter (standard library), Python 3.7+
On Linux you may need: sudo apt install python3-tk
"""

import os, sys, json, socket, struct, hashlib, platform, subprocess, tempfile
import re, shutil, threading, time
import tkinter as tk
from tkinter import ttk, messagebox
import argparse

# Allow forcing auto-elevation via CLI flag present in argv (checked early)
FORCE_ELEVATE = "--force-elevate" in sys.argv

# ──────────────────────────────────────────────────────────────
# AUTO-ELEVATE: re-launch with sudo/pkexec if not already root
# ──────────────────────────────────────────────────────────────

def _relaunch_as_root():
    """Re-launch this script with graphical sudo. Never returns on success."""
    OS = platform.system()
    script = os.path.abspath(__file__)
    py     = sys.executable

    if OS == "Linux":
        for elevator in (["pkexec", py, script],
                         ["gksudo", "--", py, script],
                         ["kdesudo", "--", py, script]):
            try:
                if shutil.which(elevator[0]):
                    os.execvp(elevator[0], elevator)
            except Exception:
                pass
        for term in (["x-terminal-emulator", "-e"],
                     ["gnome-terminal", "--"],
                     ["xterm", "-e"]):
            try:
                if shutil.which(term[0]):
                    subprocess.Popen(term + ["sudo", py, script])
                    sys.exit(0)
            except Exception:
                pass

    elif OS == "Darwin":
        apple_script = (
            f'do shell script "{py} {script}" with administrator privileges'
        )
        try:
            subprocess.Popen(["osascript", "-e", apple_script])
            sys.exit(0)
        except Exception:
            pass


if platform.system() in ("Linux", "Darwin") and os.geteuid() != 0:
    # Respect explicit force-elevate flag
    if FORCE_ELEVATE:
        _relaunch_as_root()
    else:
        # If a graphical display is available, avoid auto-elevating here because
        # graphical sudo/pkexec often loses X authentication and will prevent
        # the tkinter GUI from opening. Allow running as the regular user so the
        # GUI can start; privileged ops will prompt/elevate when needed.
        if not os.environ.get("DISPLAY"):
            _relaunch_as_root()


# ──────────────────────────────────────────────────────────────
# Core helpers
# ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def run_cmd(cmd, shell=False, timeout=10):
    try:
        r = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout)
        return r.stdout.decode(errors="replace").strip()
    except Exception:
        return None

def get_gateway_ip():
    OS = platform.system()
    if OS == "Windows":
        out = run_cmd("route print 0.0.0.0", shell=True) or ""
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0":
                return parts[2]
    elif OS == "Darwin":
        out = run_cmd(["netstat", "-nr"]) or ""
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == "default":
                return parts[1]
    else:
        out = run_cmd(["ip", "route", "show", "default"]) or ""
        for line in out.splitlines():
            parts = line.split()
            if "default" in parts:
                try:
                    return parts[parts.index("via") + 1]
                except Exception:
                    pass
    return None

def get_gateway_mac(gw_ip):
    if not gw_ip:
        return None
    if platform.system() == "Windows":
        run_cmd(f"ping -n 1 -w 1000 {gw_ip}", shell=True)
        out = run_cmd(f"arp -a {gw_ip}", shell=True) or ""
        for line in out.splitlines():
            if gw_ip in line:
                for p in line.split():
                    if "-" in p and len(p) == 17:
                        return p.upper().replace("-", ":")
    else:
        run_cmd(["ping", "-c", "1", "-W", "1", gw_ip])
        out = run_cmd(["arp", "-n", gw_ip]) or ""
        for line in out.splitlines():
            for p in line.split():
                if ":" in p and len(p) == 17:
                    return p.upper()
    return None

def get_subnet():
    if platform.system() == "Windows":
        out = run_cmd("ipconfig", shell=True) or ""
        ip = mask = None
        for line in out.splitlines():
            line = line.strip()
            if "IPv4 Address" in line:
                ip = line.split(":")[-1].strip()
            if "Subnet Mask" in line:
                mask = line.split(":")[-1].strip()
            if ip and mask:
                return mask
    else:
        out = run_cmd(["ip", "addr", "show"]) or ""
        for ip, prefix in re.findall(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', out):
            if not ip.startswith("127."):
                bits = int(prefix)
                return socket.inet_ntoa(
                    struct.pack(">I", (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
    return None

# ── USB label detection ───────────────────────────────────────

def _blkid_labels():
    labels = {}
    out = run_cmd(["blkid", "-o", "export"]) or ""
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            dev = current.get("DEVNAME", "")
            lbl = current.get("LABEL", "")
            if dev and lbl:
                labels[dev] = lbl
            current = {}
        elif "=" in line:
            k, _, v = line.partition("=")
            current[k.strip()] = v.strip()
    dev = current.get("DEVNAME", "")
    lbl = current.get("LABEL", "")
    if dev and lbl:
        labels[dev] = lbl
    return labels

def _size_str(bytes_val):
    try:
        b = float(bytes_val)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
    except Exception:
        pass
    return ""

def _is_sys_block_removable(dev_name):
    if not dev_name:
        return False
    path = os.path.join("/sys/class/block", dev_name)
    if os.path.isdir(path):
        rem = os.path.join(path, "removable")
        if os.path.exists(rem):
            try:
                return open(rem).read().strip() == "1"
            except Exception:
                pass
    base = re.sub(r'(p?\d+)$', '', dev_name)
    if base != dev_name:
        return _is_sys_block_removable(base)
    return False

def _mount_point_for_device(dev_path):
    if not dev_path.startswith("/dev/"):
        return ""
    target = run_cmd(["findmnt", "-rn", "-o", "TARGET", "--source", dev_path])
    if target:
        return target.strip()
    if os.path.exists("/proc/mounts"):
        with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if parts and parts[0] == dev_path:
                    return parts[1]
    return ""

def _scan_usb_devices_sysfs():
    drives = []
    labels = _blkid_labels()
    for name in sorted(os.listdir("/sys/class/block")):
        if name.startswith(("loop", "ram", "sr", "fd")):
            continue
        base_name = re.sub(r'(p?\d+)$', '', name)
        if not _is_sys_block_removable(base_name):
            continue
        device = f"/dev/{name}"
        mountpoint = _mount_point_for_device(device)
        vol_label = labels.get(device, "") or name
        size_str = ""

        if mountpoint:
            display = f"{vol_label}  [{mountpoint}]"
            path = mountpoint
            unmounted = False
        else:
            display = f"{vol_label}  [{device} — unmounted]"
            path = device
            unmounted = True

        drives.append({
            "path":       path,
            "mountpoint": mountpoint,
            "name":       vol_label,
            "display":    display,
            "size":       size_str,
            "serial":     "",
            "device":     device,
            "unmounted":  unmounted,
        })
    return drives

def _mount_device(device_path):
    if not os.path.exists(device_path):
        raise FileNotFoundError(device_path)
    if os.path.isdir(device_path):
        return device_path, False
    mount_dir = tempfile.mkdtemp(prefix="nextbit_usb_")
    try:
        subprocess.run(["mount", device_path, mount_dir], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return mount_dir, True
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(mount_dir, ignore_errors=True)
        raise RuntimeError(f"Cannot mount {device_path}: {exc.stderr.decode().strip()}")

def _unmount_path(mount_path, cleanup=False):
    try:
        subprocess.run(["umount", mount_path], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    if cleanup and os.path.isdir(mount_path):
        try:
            shutil.rmtree(mount_path)
        except Exception:
            pass

def list_usb_drives_linux():
    drives = _scan_usb_devices_sysfs()
    if drives:
        return drives

    labels = _blkid_labels()
    try:
        out = run_cmd([
            "lsblk", "-P", "-b",
            "-o", "NAME,TRAN,TYPE,MOUNTPOINT,RM,MODEL,VENDOR,LABEL,SIZE,SERIAL"
        ]) or ""
        for line in out.splitlines():
            props     = dict(re.findall(r'(\w+)="([^"]*)"', line))
            mount     = props.get("MOUNTPOINT", "").strip()
            removable = props.get("RM", "0").strip()
            transport = props.get("TRAN", "").strip().lower()
            dev_name  = props.get("NAME", "").strip()

            usb_candidate = (
                removable == "1"
                or transport == "usb"
                or _is_sys_block_removable(dev_name)
            )
            if not usb_candidate:
                continue

            dev_node  = f"/dev/{dev_name}"
            vol_label = (
                labels.get(dev_node, "")
                or props.get("LABEL",  "").strip()
                or props.get("MODEL",  "").strip()
                or props.get("VENDOR", "").strip()
                or "USB Drive"
            )
            size_str = _size_str(props.get("SIZE", ""))
            serial   = props.get("SERIAL", "").strip()
            size_p   = f"  [{size_str}]" if size_str else ""
            serial_p = f"  S/N:{serial}" if serial   else ""
            display  = f"{vol_label}{size_p}{serial_p}"

            if mount:
                drives.append({
                    "path":       mount,
                    "mountpoint": mount,
                    "name":       vol_label,
                    "display":    f"{display}  [{mount}]",
                    "size":       size_str,
                    "serial":     serial,
                    "device":     dev_node,
                    "unmounted":  False,
                })
            else:
                drives.append({
                    "path":       dev_node,
                    "mountpoint": "",
                    "name":       vol_label,
                    "display":    f"{display}  [{dev_node} — unmounted]",
                    "size":       size_str,
                    "serial":     serial,
                    "device":     dev_node,
                    "unmounted":  True,
                })
    except Exception:
        pass

    # Deduplicate drives by device or mountpoint (some systems list both)
    unique = []
    seen = set()
    for d in drives:
        key = (d.get("device") or d.get("path"), d.get("mountpoint") or d.get("path"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(d)
    return unique

def list_removable_drives():
    OS = platform.system()
    if OS == "Windows":
        drives = []
        out = run_cmd(
            "wmic logicaldisk where drivetype=2 get DeviceID,VolumeName,Size /format:csv",
            shell=True) or ""
        for line in out.splitlines():
            if line and "," in line and "Node" not in line:
                parts = line.split(",")
                if len(parts) >= 4:
                    device = parts[1].strip()
                    size   = _size_str(parts[2].strip())
                    label  = parts[3].strip() or "USB Drive"
                    size_p = f"  [{size}]" if size else ""
                    drives.append({
                        "path":    device,
                        "name":    label,
                        "display": f"{label}{size_p}  ({device})",
                        "size":    size,
                        "serial":  "",
                        "device":  device,
                    })
        return drives
    elif OS == "Darwin":
        drives = []
        for entry in os.listdir("/Volumes"):
            path = os.path.join("/Volumes", entry)
            if os.path.isdir(path) and path != "/Volumes/Macintosh HD":
                drives.append({
                    "path":    path,
                    "name":    entry,
                    "display": f"{entry}  ({path})",
                    "size":    "",
                    "serial":  "",
                    "device":  "",
                })
        return drives
    else:
        return list_usb_drives_linux()


def prompt_for_usb_drive(drives):
    if not drives:
        print("No USB drives detected. Plug in a removable USB drive and rerun.")
        return None
    print("Detected USB drives:")
    for idx, d in enumerate(drives, start=1):
        print(f"  {idx}. {d['display']}")
    while True:
        choice = input("Enter drive number to provision (or full path): ").strip()
        if not choice:
            print("Cancelled.")
            return None
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(drives):
                return drives[idx - 1]["path"]
            print("Invalid selection.")
            continue
        if os.path.exists(choice):
            return choice
        print("Path does not exist. Try again.")


def prompt_for_value(prompt, default=None, optional=False):
    value = input(prompt).strip()
    if not value:
        if default is not None:
            return default
        if optional:
            return ""
    return value


# ── THE FIXED copy_usb_files — duplicate block removed ────────

def copy_usb_files(target_path, usb_id, server_url, gw_ip, gw_mac, subnet):
    mount_path   = target_path
    mounted_temp = False

    # Auto-mount if target is a raw device node, not a directory
    if os.path.exists(target_path) and not os.path.isdir(target_path):
        mount_path, mounted_temp = _mount_device(target_path)

    try:
        os.makedirs(mount_path, exist_ok=True)
        os.makedirs(os.path.join(mount_path, ".nextbit"), exist_ok=True)
        os.makedirs(os.path.join(mount_path, "keys"), exist_ok=True)

        for filename in ["nextbit_probe.py", "setup_usb.py", "setup_usb_gui.py",
                         "requirements.txt", "README.md"]:
            src = os.path.join(BASE_DIR, filename)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(mount_path, filename))

        key = os.urandom(32)
        open(os.path.join(mount_path, "keys", "hmac.key"), "wb").write(key)

        fp      = {"gateway_ip": gw_ip, "gateway_mac": gw_mac, "subnet": subnet}
        fp_hash = hashlib.sha256(json.dumps(fp, sort_keys=True).encode()).hexdigest()
        json.dump({"hash": fp_hash, "preview": fp},
                  open(os.path.join(mount_path, "keys", "network.fp"), "w"), indent=2)

        json.dump({"usb_id": usb_id, "server_url": server_url},
                  open(os.path.join(mount_path, ".nextbit", "config.json"), "w"), indent=2)

        if platform.system() == "Windows":
            open(os.path.join(mount_path, "autorun.inf"), "w").write(
                "[AutoRun]\nopen=python nextbit_probe.py\nlabel=NEXTBIT Probe\n")

        if platform.system() == "Darwin":
            launch = os.path.join(mount_path, "launch.command")
            open(launch, "w").write(
                "#!/bin/bash\necho 'Run nextbit_probe.py to start the probe'\n")
            os.chmod(launch, 0o755)

        open(os.path.join(mount_path, "USB_README.txt"), "w").write(
            "NextBit Probe USB Installation\n"
            "Run nextbit_probe.py from the USB root.\n"
            "If your OS does not auto-run, open the file manually.\n")

    finally:
        if mounted_temp:
            _unmount_path(mount_path, cleanup=True)


# ──────────────────────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────────────────────

DARK_BG   = "#0d1117"
PANEL_BG  = "#161b22"
BORDER    = "#30363d"
ACCENT    = "#00d4aa"
TEXT_PRI  = "#e6edf3"
TEXT_SEC  = "#8b949e"
TEXT_MUT  = "#484f58"
SUCCESS   = "#3fb950"
WARN      = "#d29922"
ERR_CLR   = "#f85149"
FONT_MONO = ("Courier New", 10)
IS_ROOT   = (platform.system() in ("Linux", "Darwin") and os.geteuid() == 0)


class NextBitApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NextBit Probe — USB Provisioning")
        self.configure(bg=DARK_BG)
        self.resizable(False, False)

        W, H = 740, 860
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        H = min(H, sh - 60)
        self.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        self._drives         = []
        self._selected_drive = None
        self._net_info       = {}

        self._build_ui()
        self.after(120, self._scan_network)

    def _build_ui(self):
        self._footer()
        self._header()
        self._network_panel()
        self._config_panel()
        self._log_panel()
        self._usb_panel()

    def _header(self):
        hdr = tk.Frame(self, bg=DARK_BG, pady=18)
        hdr.pack(fill="x", padx=28)
        tk.Label(hdr, text="◈  NextBit Probe", fg=ACCENT, bg=DARK_BG,
                 font=("Courier New", 22, "bold")).pack(anchor="w")
        tk.Label(hdr, text="USB Provisioning Tool  ·  Run once on your store network",
                 fg=TEXT_SEC, bg=DARK_BG, font=("Courier New", 10)).pack(anchor="w", pady=(2, 4))
        badge_text  = "  ⚡ Running as Administrator — full write access" if IS_ROOT \
                 else "  ⚠  Not running as root — drive writes may fail"
        badge_color = SUCCESS if IS_ROOT else WARN
        tk.Label(hdr, text=badge_text, fg=badge_color, bg=DARK_BG,
                 font=("Courier New", 9, "bold")).pack(anchor="w")
        tk.Frame(self, bg=ACCENT, height=1).pack(fill="x")

    def _section(self, parent, title):
        f = tk.Frame(parent, bg=PANEL_BG, bd=0,
                     highlightbackground=BORDER, highlightthickness=1)
        f.pack(fill="x", padx=28, pady=(12, 0))
        tk.Label(f, text=f"  {title}", fg=TEXT_SEC, bg=PANEL_BG,
                 font=("Courier New", 8, "bold"), pady=6).pack(anchor="w")
        tk.Frame(f, bg=BORDER, height=1).pack(fill="x")
        body = tk.Frame(f, bg=PANEL_BG, padx=14, pady=10)
        body.pack(fill="x")
        return body

    def _field_row(self, parent, label, var, readonly=False, placeholder=""):
        row = tk.Frame(parent, bg=PANEL_BG)
        row.pack(fill="x", pady=4)
        tk.Label(row, text=label, fg=TEXT_SEC, bg=PANEL_BG,
                 font=FONT_MONO, width=18, anchor="w").pack(side="left")
        state = "readonly" if readonly else "normal"
        e = tk.Entry(row, textvariable=var,
                     bg=PANEL_BG if readonly else "#0d1117",
                     fg=ACCENT   if readonly else TEXT_PRI,
                     insertbackground=ACCENT, relief="flat", font=FONT_MONO, bd=4,
                     highlightbackground=BORDER, highlightthickness=1,
                     highlightcolor=ACCENT, readonlybackground=PANEL_BG, state=state)
        e.pack(side="left", fill="x", expand=True)
        if placeholder:
            self._add_placeholder(e, var, placeholder)
        return e

    def _add_placeholder(self, entry, var, text):
        if not var.get():
            entry.insert(0, text)
            entry.config(fg=TEXT_MUT)
        def fi(_):
            if entry.get() == text:
                entry.delete(0, "end")
                entry.config(fg=TEXT_PRI)
        def fo(_):
            if not entry.get():
                entry.insert(0, text)
                entry.config(fg=TEXT_MUT)
        entry.bind("<FocusIn>",  fi)
        entry.bind("<FocusOut>", fo)

    def _network_panel(self):
        body = self._section(self, "NETWORK FINGERPRINT")
        self._v_gw_ip  = tk.StringVar(value="Scanning…")
        self._v_gw_mac = tk.StringVar(value="Scanning…")
        self._v_subnet = tk.StringVar(value="Scanning…")
        self._field_row(body, "Gateway IP",  self._v_gw_ip,  readonly=True)
        self._field_row(body, "Gateway MAC", self._v_gw_mac, readonly=True)
        self._field_row(body, "Subnet Mask", self._v_subnet, readonly=True)

    def _config_panel(self):
        body = self._section(self, "USB CONFIGURATION")
        self._v_usb_id  = tk.StringVar()
        self._v_srv_url = tk.StringVar()
        self._field_row(body, "USB ID",     self._v_usb_id,
                        placeholder="e.g. NB-USB-001")
        self._field_row(body, "Server URL", self._v_srv_url,
                        placeholder="https://api.nextbit.co.ke/scan  (optional)")

    def _log_panel(self):
        body = self._section(self, "LOG")
        self._log_box = tk.Text(
            body, bg="#0d1117", fg=TEXT_PRI, relief="flat",
            font=FONT_MONO, height=5, bd=0,
            highlightbackground=BORDER, highlightthickness=0,
            state="disabled", wrap="word")
        self._log_box.pack(fill="both", expand=True)
        self._log_box.tag_config("ok",   foreground=SUCCESS)
        self._log_box.tag_config("warn", foreground=WARN)
        self._log_box.tag_config("err",  foreground=ERR_CLR)
        self._log_box.tag_config("info", foreground=ACCENT)

    def _usb_panel(self):
        body = self._section(self, "SELECT USB DRIVE")
        hdr = tk.Frame(body, bg=PANEL_BG)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Detected drives:", fg=TEXT_SEC, bg=PANEL_BG,
                 font=FONT_MONO).pack(side="left")
        tk.Button(hdr, text="↻  Rescan", fg=ACCENT, bg=PANEL_BG,
                  activeforeground=TEXT_PRI, activebackground=BORDER,
                  relief="flat", font=("Courier New", 9, "bold"), cursor="hand2",
                  bd=0, padx=8, pady=2,
                  command=self._rescan_drives).pack(side="right")
        frame = tk.Frame(body, bg=BORDER, bd=1)
        frame.pack(fill="x", pady=(6, 0))
        sb = tk.Scrollbar(frame, orient="vertical")
        self._drive_list = tk.Listbox(
            frame, bg="#0d1117", fg=TEXT_PRI,
            selectbackground=ACCENT, selectforeground=DARK_BG,
            relief="flat", bd=0, font=("Courier New", 11), height=4,
            activestyle="none", yscrollcommand=sb.set,
            highlightbackground=BORDER, highlightthickness=0)
        sb.config(command=self._drive_list.yview)
        self._drive_list.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        sb.pack(side="right", fill="y")
        self._drive_list.bind("<<ListboxSelect>>", self._on_drive_select)
        sel_row = tk.Frame(body, bg=PANEL_BG)
        sel_row.pack(fill="x", pady=(10, 0))
        tk.Label(sel_row, text="Selected:", fg=TEXT_SEC, bg=PANEL_BG,
                 font=FONT_MONO, width=18, anchor="w").pack(side="left")
        self._v_selected = tk.StringVar(value="— tap a drive above to select —")
        tk.Label(sel_row, textvariable=self._v_selected,
                 fg=ACCENT, bg=PANEL_BG,
                 font=("Courier New", 10, "bold"),
                 wraplength=520, justify="left").pack(side="left", fill="x")
        self._populate_drives()

    def _footer(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="bottom")
        foot = tk.Frame(self, bg=DARK_BG, pady=14)
        foot.pack(fill="x", padx=28, side="bottom")
        self._progress = ttk.Progressbar(foot, mode="determinate")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor=PANEL_BG, background=ACCENT,
                        bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
        self._progress.pack(fill="x", pady=(0, 10))
        self._build_btn = tk.Button(
            foot, text="▶   BUILD USB",
            fg=DARK_BG, bg=ACCENT,
            activeforeground=DARK_BG, activebackground="#00b899",
            font=("Courier New", 14, "bold"), relief="flat", bd=0,
            padx=20, pady=13, cursor="hand2",
            command=self._start_build)
        self._build_btn.pack(fill="x")

    def _populate_drives(self):
        self._drives = list_removable_drives()
        self._drive_list.delete(0, "end")
        if self._drives:
            for d in self._drives:
                self._drive_list.insert("end", f"  💾  {d['display']}")
            self._log(f"Found {len(self._drives)} USB drive(s)", "ok")
        else:
            self._drive_list.insert(
                "end", "  No USB drives found — plug in drive and click  ↻ Rescan")
            self._drive_list.itemconfig(0, foreground=WARN)
            self._log("No USB drives detected", "warn")

    def _rescan_drives(self):
        self._selected_drive = None
        self._v_selected.set("— tap a drive above to select —")
        self._log("Rescanning drives…", "info")
        self._populate_drives()

    def _on_drive_select(self, _event):
        sel = self._drive_list.curselection()
        if not sel or not self._drives:
            return
        idx = sel[0]
        if idx < len(self._drives):
            d = self._drives[idx]
            self._selected_drive = d
            self._v_selected.set(d['display'])
            self._log(f"Selected: {d['display']}", "info")

    def _scan_network(self):
        def worker():
            gw_ip  = get_gateway_ip()
            gw_mac = get_gateway_mac(gw_ip)
            subnet = get_subnet()
            self._net_info = {"gw_ip": gw_ip, "gw_mac": gw_mac, "subnet": subnet}
            self.after(0, self._update_net_ui, gw_ip, gw_mac, subnet)
        threading.Thread(target=worker, daemon=True).start()

    def _update_net_ui(self, gw_ip, gw_mac, subnet):
        self._v_gw_ip.set(gw_ip   or "NOT FOUND")
        self._v_gw_mac.set(gw_mac or "NOT FOUND")
        self._v_subnet.set(subnet  or "NOT FOUND")
        if gw_ip:
            self._log(f"Network detected  ·  Gateway: {gw_ip}", "ok")
        else:
            self._log("No gateway found — connect to store network first", "err")

    def _start_build(self):
        usb_id = self._v_usb_id.get().strip()
        if not usb_id or usb_id.startswith("e.g."):
            messagebox.showerror("Missing USB ID", "Enter a USB ID, e.g.  NB-USB-001")
            return
        if not self._selected_drive:
            messagebox.showerror("No Drive Selected", "Select a USB drive from the list first.")
            return
        if not self._net_info.get("gw_ip"):
            messagebox.showerror("No Network",
                                 "No gateway found.\nConnect to your store network first.")
            return

        srv = self._v_srv_url.get().strip()
        if "optional" in srv or srv == "":
            srv = ""

        d      = self._selected_drive
        target = d["path"]

        ok = messagebox.askyesno(
            "Confirm — Write to USB?",
            f"Ready to provision this drive:\n\n"
            f"  Drive   : {d['display']}\n"
            f"  Path    : {target}\n"
            f"  USB ID  : {usb_id}\n"
            f"  Gateway : {self._net_info['gw_ip']}\n\n"
            "Files will be written to the drive. Continue?"
        )
        if not ok:
            return

        self._build_btn.config(state="disabled", text="⏳  Working…")
        threading.Thread(
            target=self._run_build,
            args=(target, usb_id, srv,
                  self._net_info.get("gw_ip"),
                  self._net_info.get("gw_mac"),
                  self._net_info.get("subnet")),
            daemon=True
        ).start()

    def _run_build(self, target, usb_id, srv, gw_ip, gw_mac, subnet):
        steps = [
            ("Capturing network fingerprint",         20),
            ("Creating directory structure",           40),
            ("Writing HMAC key & network fingerprint", 60),
            ("Copying probe files",                    80),
            ("Finalising configuration",              100),
        ]
        try:
            for msg, pct in steps:
                self.after(0, self._log, msg + "…", "info")
                self.after(0, self._set_progress, pct)
                time.sleep(0.25)

            copy_usb_files(target, usb_id, srv, gw_ip, gw_mac, subnet)

            self.after(0, self._log, "✓ USB provisioning complete!", "ok")
            self.after(0, self._log, f"  Drive  : {target}", "ok")
            self.after(0, self._log, f"  USB ID : {usb_id}", "ok")
            if not srv:
                self.after(0, self._log, "  Mode   : standalone (no server URL)", "warn")

            self.after(0, messagebox.showinfo, "Done ✓",
                       f"USB provisioned successfully!\n\n"
                       f"Drive  : {target}\n"
                       f"USB ID : {usb_id}\n"
                       f"Gateway: {gw_ip} ({gw_mac or 'MAC unknown'})")
        except PermissionError as e:
            self.after(0, self._log, f"✗ Permission denied: {e}", "err")
            self.after(0, messagebox.showerror, "Permission Denied",
                       f"Cannot write to {target}.\n\nRun as root:\n  sudo python setup_usb.py")
        except Exception as e:
            self.after(0, self._log, f"✗ Error: {e}", "err")
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.after(0, self._build_btn.config,
                       {"state": "normal", "text": "▶   BUILD USB"})

    def _log(self, msg, tag="info"):
        self._log_box.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self._log_box.insert("end", f"[{ts}]  {msg}\n", tag)
        self._log_box.see("end")
        self._log_box.config(state="disabled")

    def _set_progress(self, value):
        self._progress["value"] = value


# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NextBit Probe USB Provisioning")
    parser.add_argument('--usb-id',     help='USB ID, e.g. NB-USB-001')
    parser.add_argument('--server-url', help='Server URL (optional)')
    parser.add_argument('--drive-path', help='Path to USB drive mount point or device node')
    parser.add_argument('--list-drives', action='store_true',
                        help='List removable USB drives and exit')
    args = parser.parse_args()

    if args.list_drives:
        drives = list_removable_drives()
        if not drives:
            print("No removable USB drives found.")
            sys.exit(1)
        print("Detected removable USB drives:")
        for idx, d in enumerate(drives, start=1):
            print(f"  {idx}. {d['display']}")
        sys.exit(0)

    if args.usb_id and args.drive_path:
        print("Running in headless mode...")
        gw_ip  = get_gateway_ip()
        gw_mac = get_gateway_mac(gw_ip)
        subnet = get_subnet()
        srv    = args.server_url or ""
        try:
            copy_usb_files(args.drive_path, args.usb_id, srv, gw_ip, gw_mac, subnet)
            print("✓ USB provisioning complete!")
            print(f"  Drive  : {args.drive_path}")
            print(f"  USB ID : {args.usb_id}")
            if not srv:
                print("  Mode   : standalone (no server URL)")
        except Exception as e:
            print(f"✗ Error: {e}")
            sys.exit(1)
        sys.exit(0)

    if not os.environ.get("DISPLAY") and sys.stdin.isatty():
        print("No display available. Running in terminal provisioning mode.")
        if not args.drive_path:
            drives = list_removable_drives()
            args.drive_path = prompt_for_usb_drive(drives)
            if not args.drive_path:
                sys.exit(1)
        if not args.usb_id:
            args.usb_id = prompt_for_value("USB ID (e.g. NB-USB-001): ")
            if not args.usb_id:
                print("USB ID is required.")
                sys.exit(1)
        gw_ip  = get_gateway_ip()
        gw_mac = get_gateway_mac(gw_ip)
        subnet = get_subnet()
        srv    = args.server_url or ""
        try:
            copy_usb_files(args.drive_path, args.usb_id, srv, gw_ip, gw_mac, subnet)
            print("✓ USB provisioning complete!")
            print(f"  Drive  : {args.drive_path}")
            print(f"  USB ID : {args.usb_id}")
            if not srv:
                print("  Mode   : standalone (no server URL)")
        except Exception as e:
            print(f"✗ Error: {e}")
            sys.exit(1)
        sys.exit(0)

    try:
        app = NextBitApp()
        app.mainloop()
    except tk.TclError as e:
        if "no display" in str(e).lower():
            print("No display available. Use --usb-id and --drive-path flags, or run interactively.")
            sys.exit(1)
        else:
            raise