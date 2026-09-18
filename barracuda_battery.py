#!/usr/bin/env python3
"""
Razer Barracuda X (2.4 GHz dongle, VID:PID 1532:0536) battery reader over HID.

Protocol (reverse-engineered; same Macronix dongle generation as the Razer Nari):

  1. SET_REPORT(Feature, report id 0xFF), 64 bytes:
         ff 0a 00 fd 04 12 f1 02 05 <55 x 00>
     (the same state/battery query Razer Synapse sends every few seconds)
  2. GET_REPORT(Feature, report id 0xFF) -> 64-byte state blob:
         [0]     0xFF  report-id echo
         [9]     charge status: 0x03 discharging, 0x05 charging, 0x06 fully charged
         [12:14] battery voltage, uint16 big-endian, millivolts
         [14]    battery percent, firmware-reported

  The 90-byte Synapse/razer_report protocol (used by the Barracuda 1532:053C)
  is NOT supported by this dongle - it STALLs (EPIPE). Don't use it.

CLI:
  barracuda_battery.py              one-shot, human readable
  barracuda_battery.py --json       machine readable (for tray apps)
  barracuda_battery.py -v           include raw state hex
  barracuda_battery.py --dev PATH   override device (default: auto-detect)

Library:
  from barracuda_battery import read_state
  s = read_state()                  # -> {'percent', 'millivolts', 'status', 'raw', 'device'}
"""
import fcntl
import glob
import os
import sys
import time

VID = 0x1532
PIDS = (0x0536, 0x0552, 0x0574)          # Barracuda X / Barracuda X 2.4 / Barracuda X Chroma
IOC = lambda nr, n: 0xC0000000 | (n << 16) | (0x48 << 8) | nr   # HIDIOCSFEATURE(6)/HIDIOCGFEATURE(7)
QUERY = bytes([0xFF, 0x0A, 0x00, 0xFD, 0x04, 0x12, 0xF1, 0x02, 0x05] + [0] * 55)
STATUS = {0x00: "idle", 0x03: "discharging", 0x05: "charging", 0x06: "fully charged"}


def find_hidraw():
    """Auto-detect the Barracuda X dongle's hidraw node via /sys (survives replugs)."""
    for dev in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            with open(f"{dev}/device/uevent") as f:
                for line in f:
                    if line.startswith("HID_ID="):
                        _, vid, pid = line.strip().split(":")
                        if int(vid, 16) == VID and int(pid, 16) in PIDS:
                            return "/dev/" + os.path.basename(dev)
        except OSError:
            continue
    return None


def read_state(dev=None):
    """Query the dongle once. Returns dict with percent / millivolts / status / raw / device."""
    if dev is None:
        dev = find_hidraw()
        if dev is None:
            raise FileNotFoundError("Barracuda X dongle not found (no HID 1532:0536/0552/0574 present)")

    fd = os.open(dev, os.O_RDWR)
    try:
        fcntl.ioctl(fd, IOC(6, 64), bytearray(QUERY))      # SET_REPORT: arm the query
        buf = bytearray(64)
        buf[0] = 0xFF
        fcntl.ioctl(fd, IOC(7, 64), buf)                   # GET_REPORT: read state cache
    finally:
        os.close(fd)

    d = bytes(buf)
    percent = d[14]
    if percent > 100:
        raise ValueError(f"implausible state from {dev}: {d.hex(' ')}")
    return {
        "percent": percent,
        "millivolts": (d[12] << 8) | d[13],
        "status": STATUS.get(d[9], f"unknown(0x{d[9]:02x})"),
        "raw": d.hex(" "),
        "device": dev,
        "unix_time": time.time(),
    }


def main():
    argv = sys.argv[1:]
    dev = None
    if "--dev" in argv:
        i = argv.index("--dev")
        dev = argv[i + 1]
        del argv[i:i + 2]
    try:
        s = read_state(dev)
    except (OSError, ValueError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")
    if "--json" in argv:
        import json
        print(json.dumps(s, indent=2))
    else:
        print(f"Battery: {s['percent']}% ({s['millivolts']} mV, {s['status']})")
        if "-v" in argv or "--verbose" in argv:
            print("raw:", s["raw"])


if __name__ == "__main__":
    main()