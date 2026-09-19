#!/usr/bin/env python3
"""
Razer Barracuda X / Barracuda Pro battery reader over HID.

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
* Barracuda Pro 2.4 (053a): "PA" frames over the vendor INTERRUPT endpoints
  (EP 3 OUT / EP 4 IN, 64-byte packets, report id 0x01):

      request:  01 80 <len> 50 41 <class> <arglen> <cmd> <args..>
      response: 01 80 <len> 50 49 01 c0 <seq..> <data..>

  class 0x08 = Synapse settings channel (read 03 <param> 00, write 04 ...;
  no battery param there - a 256-param sweep answered only 0x01/0x20).
  class 0x02 = line-oriented firmware console, class 0x09 = status channel.
  Both the console "bat" line and a class-09 cmd-04 query have returned the
  36-byte battery status frame:

      01 00 26 00 09 88 <36-byte payload>

      payload[4..7]   u32 charge state (0x07 observed while charging)
      payload[8..11]  u32 charge level in percent (0x56 = 86)
      payload[12..]   ms-resolution timers (one = dongle uptime)

  The console is state-dependent: fresh after a replug it runs in "data
  mode" (payload text never reaches the command line -> "X is not a valid
  command"), an arglen overrun wedges it silent until the next replug, and
  in its "append mode" (observed once, trigger unknown) the "bat" line
  works.  Console replies can queue for 2-13 s and are flushed by the next
  write.  This reader probes the console line, a class-09 cmd-04 query and
  the console line again with a longer window, scanning every reply for
  the blob marker 26 00 09 88 and reporting console errors verbatim.
  Full write-up: docs/barracudapro.md.

  WARNING: Pro probing is EXPERIMENTAL.  The frames above are
  reverse-engineered guesses (the class-09 cmd-04 query is invented), and a
  probe burst has already hung this dongle - audio playback died until the
  dongle was replugged.  Never let arglen differ from the payload length,
  avoid bursts and polling loops (barracuda-watch/barracuda-tray) on a 053a
  dongle, and keep a replug handy.  See docs/barracudapro.md §7.

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
import select
import sys
import time

VID = 0x1532
X_PIDS = (0x0536, 0x0552, 0x0574)         # Barracuda X / X 2.4 / X Chroma
PRO_PIDS = (0x053A,)                      # Barracuda Pro 2.4
ALL_PIDS = X_PIDS + PRO_PIDS
IOC = lambda nr, n: 0xC0000000 | (n << 16) | (0x48 << 8) | nr   # HIDIOCSFEATURE(6)/HIDIOCGFEATURE(7)
QUERY = bytes([0xFF, 0x0A, 0x00, 0xFD, 0x04, 0x12, 0xF1, 0x02, 0x05] + [0] * 55)
STATUS = {0x00: "idle", 0x03: "discharging", 0x05: "charging", 0x06: "fully charged"}


def find_hidraw():
    """Auto-detect a Barracuda dongle's hidraw node via /sys (survives replugs).

    Returns (hidraw_path, pid) or (None, None).
    """
    for dev in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            with open(f"{dev}/device/uevent") as f:
                for line in f:
                    if line.startswith("HID_ID="):
                        _, vid, pid = line.strip().split(":")
                        if int(vid, 16) == VID and int(pid, 16) in ALL_PIDS:
                            return "/dev/" + os.path.basename(dev), int(pid, 16)
        except OSError:
            continue
    return None, None


def _hidraw_pid(dev):
    """Resolve the USB PID of an hidraw node (None if unknown)."""
    name = os.path.basename(dev)
    try:
        with open(f"/sys/class/hidraw/{name}/device/uevent") as f:
            for line in f:
                if line.startswith("HID_ID="):
                    _, vid, pid = line.strip().split(":")
                    return int(pid, 16)
    except OSError:
        pass
    return None


def _x_read_state(dev):
    """Barracuda X family: 0xFF feature report SET/GET cycle."""
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
        "pid": None,
        "unix_time": time.time(),
    }


def _frame(cls, payload):
    """Build a 64-byte Pro 'PA' frame (EP 3 OUT, report id 0x01).

    arglen and the length byte are derived from the payload, so they can
    never disagree - an arglen overrun wedges the dongle's frame parser."""
    if not 0 <= len(payload) <= 57:                   # 7-byte header
        raise ValueError(f"Pro frame payload too long: {len(payload)} bytes (max 57)")
    f = bytearray(64)
    f[0] = 1
    f[1] = 0x80
    f[3] = 0x50
    f[4] = 0x41
    f[5] = cls
    f[6] = len(payload)
    f[7:7 + len(payload)] = payload
    f[2] = 4 + len(payload)
    return f


def _parse_blob(buf):
    """Extract (state_code, percent, payload) from a Pro status blob, else None.

    Frame: `01 00 26 00 09 88 <36-byte payload>`.  The charge state and percent
    are u32-aligned fields at payload[4]/payload[8]; one early capture was
    analysed with the counter starting at the `09 88` bytes, so the shifted
    reading (payload[2]/payload[6]) is kept as a fallback.  See
    docs/barracudapro.md §4."""
    marker = buf.find(b"\x26\x00\x09\x88")            # len 0x26, ctr, type 09, seq 88
    if marker < 0 or len(buf) < marker + 4 + 36:
        return None
    payload = buf[marker + 4: marker + 4 + 36]       # the 36 status bytes
    for state_code, percent in ((payload[4], payload[8]),    # u32-aligned
                                (payload[2], payload[6])):   # shifted (early reading)
        if percent <= 100:
            return state_code, percent, payload
    return None


def _console_line(buf):
    """Pull the command name out of a console "... is not a valid command" reply."""
    i = buf.find(b"is not a valid command")
    if i < 0:
        return ""
    line = buf[:i].rsplit(b"\r\n", 1)[-1].rsplit(b"\n", 1)[-1]  # last console line
    txt = "".join(chr(c) if 32 <= c < 127 else "" for c in line).strip()
    return txt or "<empty>"


def _pro_read_state(dev):
    """Barracuda Pro: query the battery via console / status class.

    The Pro's console is state-dependent (fresh = data mode, payload text
    never reaches the command line; arglen overrun = silent wedge until
    replug; append mode = the `bat` line works).  Probe shapes tried in
    order: the console `bat` line, a class-09 cmd-04 query, then the `bat`
    line again with a longer window (each write also flushes earlier queued
    replies).  Every reply is scanned for the 36-byte status blob; console
    errors are collected for the diagnostics.  See docs/barracudapro.md.

    EXPERIMENTAL: this traffic is guessed (see the module docstring warning);
    a probe burst has hung the dongle before (audio lost until replug).  Keep
    every frame length-consistent and avoid polling loops on a 053a dongle."""
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    try:
        # drop stale queued console output
        try:
            while select.select([fd], [], [], 0)[0]:
                os.read(fd, 64)
        except OSError:
            pass

        probes = (
            ("console bat", 0x02, b"\x08\x08\x08bat\r\n", 6.0),
            ("cls09 cmd04", 0x09, bytes([0x04, 0, 0, 0, 0, 0, 0, 0]), 4.0),
            ("console bat retry", 0x02, b"\x08\x08\x08bat\r\n", 12.0),
        )
        console_err = ""
        for name, cls, payload, window in probes:
            try:
                os.write(fd, _frame(cls, payload))
            except OSError as e:
                raise OSError(f"{dev}: write failed ({e}); dongle may need a replug") from e

            buf = b""
            err_seen_at = None
            end = time.time() + window
            while time.time() < end:
                r, _, _ = select.select([fd], [], [], 0.1)
                if not r:
                    continue
                try:
                    buf += os.read(fd, 64)
                except OSError:
                    break
                parsed = _parse_blob(buf)
                if parsed:
                    state_code, percent, blob = parsed
                    return {
                        "percent": percent,
                        "millivolts": None,            # the blob carries no voltage
                        "status": {7: "charging"}.get(state_code, f"code {state_code}"),
                        "raw": blob.hex(" "),
                        "device": dev,
                        "pid": 0x053A,
                        "unix_time": time.time(),
                    }
                if b"is not a valid command" in buf and err_seen_at is None:
                    err_seen_at = time.time()         # console answered: data mode
                    if not console_err:
                        console_err = _console_line(buf)
                if err_seen_at is not None and time.time() - err_seen_at > 1.5:
                    break                            # error seen, blob won't follow

        if console_err:
            raise TimeoutError(
                f"no battery status frame from {dev}; the console is in data mode "
                f"and rejected the probe (replied {console_err!r}) - see "
                "docs/barracudapro.md §3")
        raise TimeoutError(
            f"no battery status frame from {dev} (console silent; "
            "dongle may need a replug)")
    finally:
        os.close(fd)


def read_state(dev=None):
    """Query the dongle once. Returns dict with percent / millivolts / status / raw / device.

    'millivolts' is None on the Pro (its console blob carries no voltage)."""
    if dev is None:
        dev, pid = find_hidraw()
        if dev is None:
            raise FileNotFoundError("Barracuda dongle not found (no HID 1532:0536/0552/0574/053a present)")
        pro = pid in PRO_PIDS
    else:
        pid = _hidraw_pid(dev)
        if pid is None:
            raise FileNotFoundError(f"cannot read uevent for {dev}")
        pro = pid in PRO_PIDS
    if pro:
        return _pro_read_state(dev)
    return _x_read_state(dev)


def main():
    argv = sys.argv[1:]
    dev = None
    if "--dev" in argv:
        i = argv.index("--dev")
        dev = argv[i + 1]
        del argv[i:i + 2]
    try:
        s = read_state(dev)
    except (OSError, ValueError, TimeoutError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")
    if "--json" in argv:
        import json
        print(json.dumps(s, indent=2))
    else:
        mv = s["millivolts"]
        mv_txt = f" ({mv} mV)" if mv is not None else ""
        print(f"Battery: {s['percent']}%{mv_txt}, {s['status']}")
        if "-v" in argv or "--verbose" in argv:
            print("raw:", s["raw"])


if __name__ == "__main__":
    main()