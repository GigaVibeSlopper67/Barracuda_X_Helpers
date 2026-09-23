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
  (EP 3 OUT / EP 4 IN, 64-byte HID report id 0x01 - confirmed by the config
  descriptor and by Synapse traffic, docs/barracudapro.md §8):

      request:  01 80 <len> 50 41 <class> <arglen> <cmd> <args..>
      response: 01 80 <len> 50 49 <class> <seq> <tick3> <data..>

  <len> = 4 + the argument bytes after <arglen>/<seq>.  For class 0x08 the
  <arglen> byte is a constant 0x08 (not the payload length) and replies arrive
  11-20 ms after the request with no flush frame needed; frames the dongle
  pushes on its own carry kind 0x02 instead of 0x01.  See §8 of the write-up.

  class 0x08 = Synapse settings channel.  This is the ONLY channel Synapse was
  ever observed using (read `03 <param> 00 00`, write `04 <param> 00 <len>
  <val>`), so it is the only one this reader sends by default.  Battery
  percent is class-08 param 0x21 (verified against Synapse's UI: 0x5d = 93%
  in the bare-metal capture) with a charge-state byte on param 0x2a (0x00
  discharging, 0x01 charging).
  A fresh sweep with Synapse-shaped frames is `--sweep`.
  class 0x02 = line-oriented debug console, class 0x09 = status channel.  Both
  have returned the 36-byte battery status frame:

      01 00 26 00 09 88 <36-byte payload>

      payload[4..7]   u32 charge state (0x07 observed while charging)
      payload[8..11]  u32 charge level in percent (0x56 = 86)
      payload[12..]   ms-resolution timers (one = dongle uptime)

  but Synapse never uses either class, and the console is state-dependent
  (fresh = "data mode", where payload text never reaches the command line; its
  reply queue can lag 2-13 s).  They are the prime suspect for the hangs this
  dongle suffers, so they are opt-in only: `--legacy-console-probes`.

  WARNING: `--legacy-console-probes` is EXPERIMENTAL and has killed audio
  until a USB replug (docs/barracudapro.md §7).  The default path is much
  safer: a single Synapse-shaped class-08 read (param 0x20 link flag, which
  always answers on a healthy dongle) decides whether the dongle is answering,
  and nothing else is sent unless a battery parameter has been identified.

CLI:
  barracuda_battery.py              one-shot, human readable
  barracuda_battery.py --json       machine readable (for tray apps)
  barracuda_battery.py -v           include raw state hex
  barracuda_battery.py --dev PATH   override device (default: auto-detect)
  barracuda_battery.py --sweep [LO-HI] [--pace S] [--dry-run]
                                    look for a class-08 battery param with
                                    Synapse-shaped reads (default 0x00-0x7f)
  barracuda_battery.py --watch [SECONDS]
                                    live battery/status/link-signal (0x33) reads
  barracuda_battery.py --info        read the version/identifier param (0x00)
  barracuda_battery.py --probe-status
                                    probe the class-0x0e status poll (opt-in)
  barracuda_battery.py --features
                                    warm up + read all feature-candidate params
  barracuda_battery.py --set-anc off|on|ambient
                                    write ANC mode (param 0x92), verify by read
  barracuda_battery.py --set-sidetone 0-100
                                    set sidetone level (percent -> 0-15 scale)
  barracuda_battery.py --set-power-save 0-60
                                    set power-saving timeout (min, 0 = off)
  barracuda_battery.py --set 0xPARAM 0xVAL
                                    write a class-08 param (read param + 0x80)
  barracuda_battery.py --legacy-console-probes
                                    send the old class-02/0x09 guesses (can
                                    kill audio until a replug)

Library:
  from barracuda_battery import read_state
  s = read_state()                  # -> {'percent', 'millivolts', 'link', 'status', 'raw', 'device', 'pid', 'name'}
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

# Human-readable product name per dongle PID - the single source of truth for
# anything that labels a reading (tray, watch, JSON consumers).
DEVICE_NAMES = {
    0x0536: "Barracuda X",
    0x0552: "Barracuda X 2.4",
    0x0574: "Barracuda X Chroma",
    0x053A: "Barracuda Pro 2.4",
}


def device_name(pid):
    """Human-readable product name for a dongle PID ('Barracuda' if unknown)."""
    return DEVICE_NAMES.get(pid, "Barracuda")


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


def _x_read_state(dev, pid=None):
    """Barracuda X family: 0xFF feature report SET/GET cycle."""
    if pid is None:
        pid = _hidraw_pid(dev)
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
        "pid": pid,
        "name": device_name(pid),
        "unix_time": time.time(),
    }


def _frame(cls, payload, arglen=None):
    """Build a 64-byte Pro 'PA' frame (EP 3 OUT, report id 0x01).

    `arglen` defaults to the payload length (what our class-02/09 probes use).
    A Synapse capture showed that class-08 requests always carry arglen 0x08
    no matter what the payload length is, so pass arglen=8 for a
    Synapse-shaped class-08 frame (docs/barracudapro.md §8.2).

    The frame length byte is always derived from the payload, and an oversized
    payload is rejected: a frame whose arglen runs past the 64-byte report
    wedges the dongle's parser (see docs/barracudapro.md §7)."""
    if not 0 <= len(payload) <= 57:                   # 7-byte header
        raise ValueError(f"Pro frame payload too long: {len(payload)} bytes (max 57)")
    if arglen is not None and not 0 <= arglen <= 57:
        raise ValueError(f"Pro frame arglen out of range: {arglen} (0..57)")
    f = bytearray(64)
    f[0] = 1
    f[1] = 0x80
    f[3] = 0x50
    f[4] = 0x41
    f[5] = cls
    f[6] = len(payload) if arglen is None else arglen
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


# --- Pro (053a) class-08 channel - verified against Synapse's own traffic ----
# docs/barracudapro.md §8 (Synapse USBPcap capture, 2026-09-20):
#   read   01 80 08 50 41 08 08 03 <param> 00 00
#   write  01 80 09 50 41 08 08 04 <param> 00 <vlen> <val>
#   reply  01 80 0e 50 49 08 <seq> <tick3> 00 04 00 <param> <kind> 01 <value>
# arglen (byte 6) is a constant 0x08 - NOT the payload length; <len> (byte 2)
# is 4 + the argument bytes.  class 0x02 (console) and 0x09 (status) are
# unverified guesses that Synapse never sends and that have hung this dongle
# (§7) - they are reachable only through --legacy-console-probes.

PRO_ANCHOR_PARAM = 0x20          # link flag - reliable liveness check (0x12 ANC is flaky)
PRO_SWEEP_RANGE = (0x00, 0x7F)   # read-side params Synapse's UI talks to
PRO_BATTERY_PARAMS = (0x21,)     # battery percent - verified vs Synapse UI (0x5d = 93)
PRO_STATUS_PARAM = 0x2A          # charge-state byte, read right before 0x21
PRO_VERSION_PARAM = 0x00         # firmware/version string (reply ends "...IN")
PRO_SIGNAL_PARAM = 0x33          # link signal strength / RSSI (higher = stronger).
# 0x33 is NOT battery voltage - the old "(value * 20 = mV)" reading was a
# coincidence (the raw ~200 x 20 landed in the Li-ion 3.6-4.2 V window).
# Measured 2026-09-23: ~208-211 with the headset next to the dongle, falling
# monotonically to ~160 at range edge before the link dropped, recovering back
# to ~208 on return.  Unchanged by ANC toggles and by plugging in the charger
# (rules out current/load too).
# class-08 param 0x2a -> charge state.  0x00 = on battery, 0x01 = charging
# (verified 2026-09-20 by plugging/unplugging the charger).  A "fully charged"
# value has not been observed yet - watch for it once it sits at 100 % on the
# charger, and add it here.
PRO_STATUS = {
    0x00: "discharging",
    0x01: "charging",
}

# class-08 param 0x12 (ANC mode) values - all three confirmed by toggling.
PRO_ANC_VALUES = {"off": 0x00, "on": 0x0A, "ambient": 0xFF}

# Feature-candidate class-08 read params with best-guess labels.  Discovered by
# the 2026-09-20 warm-up + full sweep.  NOTE: THX/Stereo, Bass Boost, Mic Noise
# Cancellation and Volume turned out to be *software DSP in Synapse* (the fourth
# capture shows zero frames for them), so they are NOT here - these are the
# dongle-side params only.  `0x33` is the link signal strength / RSSI (higher =
# stronger), not a battery voltage.
PRO_FEATURES = [
    (0x12, "ANC mode (0 off / 10 on / 255 ambient)"),
    (0x1E, "audio EQ"),
    (0x16, "EQ 2nd param"),
    (0x17, "EQ 3rd param"),
    (0x18, "sidetone (0 off / 1 on)"),
    (0x2C, "power saving (0 off / 15-60 min)"),
    (0x2D, "power-saving timeout"),
    (0x56, "unknown hardware param"),
    (0x57, "unknown hardware param"),
    (0x33, "link signal strength / RSSI (higher = stronger)"),
    (0x25, "unknown"),
    (0x13, "unknown"),
    (0x14, "unknown"),
    (0x19, "sidetone level"),
    (0x26, "unknown"),
    (0x27, "unknown"),
    (0x55, "unknown"),
    (0x58, "unknown"),
]


def _pro_read_frame(param):
    """Synapse-shaped class-08 read: `03 <param> 00 00` with arglen 0x08."""
    return _frame(0x08, bytes([0x03, param, 0x00, 0x00]), arglen=8)


def _pi_frames(buf):
    """Decode every complete 'PI' reply found in a raw hidraw read buffer."""
    out, o = [], 0
    while o + 11 <= len(buf):
        if buf[o:o + 2] != b"\x01\x80" or buf[o + 3:o + 5] != b"PI":
            o += 1
            continue
        end = min(len(buf), o + buf[o + 2] + 3)      # <len> = 4 + bytes after [6]
        d = buf[o:end]
        f = {"class": d[5], "seq": d[6], "tick": d[7] | d[8] << 8 | d[9] << 16,
             "param": None, "kind": None, "value": None, "data": bytes(d[10:])}
        if len(d) >= 17 and d[11] == 0x04:           # 00 04 00 <param> <kind> 01 <v>
            f["param"], f["kind"], f["value"] = d[13], d[14], d[16]
        out.append(f)
        o = end if end > o else o + 1
    return out


def _pro_drain(fd):
    """Discard queued replies so a query cannot match a stale frame."""
    try:
        while select.select([fd], [], [], 0)[0]:
            os.read(fd, 64)
    except OSError:
        pass


def _pro_query(fd, param, window=0.5, attempts=2):
    """Send Synapse-shaped class-08 reads for `param`; return (reply, raw bytes).

    `reply` is the PI frame answering `param` with kind 0x01 (a reply - not an
    unsolicited event), or None if nothing matched.  Up to `attempts` identical
    reads go out: the second one also covers the "the dongle only flushes its
    reply queue when the next frame is written" behaviour seen on Linux (§3),
    so a reply can never be mistaken for silence."""
    buf = b""
    for _ in range(max(1, attempts)):
        os.write(fd, _pro_read_frame(param))
        end = time.time() + window
        while time.time() < end:
            if not select.select([fd], [], [], 0.1)[0]:
                continue
            try:
                buf += os.read(fd, 64)
            except OSError:
                return None, buf
            for f in _pi_frames(buf):
                if f["param"] == param and f["kind"] == 0x01:
                    return f, buf
    return None, buf


def _record(seen, buf):
    """Collect every reply in a read buffer, keyed by param.

    Replies are attributed by their own param field, not by which read they
    answered, so a reply that arrives one frame late is still recorded."""
    for f in _pi_frames(buf):
        if f["param"] is not None and f["kind"] == 0x01:
            seen.setdefault(f["param"], f)


def _pro_read_state(dev, console=False):
    """Barracuda Pro: read state over the Synapse-verified class-08 channel.

    Safety rules (docs/barracudapro.md §7, §8) - all learned the hard way:
      * only Synapse-shaped class-08 reads go out; Synapse's own traffic is the
        only thing proven not to hang this dongle;
      * the first frame is the link-flag read (param 0x20) that always answers
        when the dongle is alive; the ANC read (param 0x12) is flaky and would
        wrongly report a healthy dongle as wedged;
      * the class-02/class-09 probes that have killed audio are never sent
        unless `console=True` (CLI only: --legacy-console-probes).

    Battery percent is class-08 param 0x21 and the charge state is 0x2a (0x00
    discharging, 0x01 charging) - both verified against Synapse's bare-metal
    capture and a live plug/unplug of the charger."""
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    try:
        _pro_drain(fd)
        anchor, _ = _pro_query(fd, PRO_ANCHOR_PARAM, 1.0)
        if anchor is None and not console:
            raise TimeoutError(
                f"{dev}: no answer to the class-08 link read (param 0x20) - "
                "the dongle is not answering (possibly wedged); replug and "
                "re-run; see docs/barracudapro.md §9.2")
        if anchor is None:
            print(f"warning: {dev} did not answer the class-08 link read (0x20) - "
                  "it may be wedged; sending the requested legacy probes anyway",
                  file=sys.stderr)
        if console:
            return _pro_console_probe(dev)
        _pro_unlock(fd)   # unlock battery/status reads (class-0x0e poll)
        # status (0x2a) first, then percent (0x21) - Synapse's own read order.
        # Also read 0x33, the link signal strength / RSSI byte (higher = stronger).
        status_reply, _ = _pro_query(fd, PRO_STATUS_PARAM, 0.5)
        link_reply, _ = _pro_query(fd, PRO_SIGNAL_PARAM, 0.5)
        for param in PRO_BATTERY_PARAMS:
            reply, _ = _pro_query(fd, param, 0.5)
            if reply and reply["value"] is not None and reply["value"] <= 100:
                st = status_reply["value"] if status_reply else None
                status = ("unknown" if st is None
                          else PRO_STATUS.get(st, f"0x{st:02x} (unmapped)"))
                raw = (status_reply["data"] if status_reply else b"").hex(" ")
                raw += " | " + reply["data"].hex(" ")
                return {
                    "percent": reply["value"],
                    "millivolts": None,
                    "link": link_reply["value"] if link_reply else None,
                    "status": status,
                    "raw": raw,
                    "device": dev,
                    "pid": 0x053A,
                    "name": device_name(0x053A),
                    "unix_time": time.time(),
                }
        raise TimeoutError(
            f"{dev}: class-08 battery read (param 0x21) did not answer "
            f"(link flag 0x20 = {anchor['data'].hex(' ')}) - replug and re-run; "
            "docs/barracudapro.md §9")
    finally:
        os.close(fd)


def _pro_console_probe(dev):
    """Legacy probe set: class-02 console `bat` line + class-09 `cmd 04`.

    Kept byte-for-byte as it was when it produced the one battery blob we ever
    saw (docs/barracudapro.md §3/§4).  UNVERIFIED and DANGEROUS: Synapse never
    sends these, the console is a debug channel, and its arglen here is 9 while
    every Synapse frame carries 8 - the prime suspect for the hangs that kill
    audio until a replug (§7).  Reachable only via --legacy-console-probes."""
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
                        "name": device_name(0x053A),
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


def read_state(dev=None, console=False):
    """Query the dongle once. Returns dict with percent / millivolts / link / status / raw / device / pid / name.

    'millivolts' is None on the Pro (no voltage is exposed on its channel);
    instead the Pro carries 'link', the 0x33 signal-strength / RSSI byte
    (higher = stronger, ~208 beside the dongle, ~160 at range edge).  'name'
    is the model label from `device_name()` (e.g. "Barracuda X" vs
    "Barracuda Pro 2.4") so callers never have to guess the product.
    `console=True` re-enables the Pro's legacy class-02/0x09 probes - only the
    CLI does that (--legacy-console-probes), because they have killed audio."""
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
        return _pro_read_state(dev, console)
    return _x_read_state(dev, pid)


def _pro_sweep(dev, lo, hi, pace=0.25, dry_run=False, max_fail=3):
    """Hunt for a class-08 battery parameter with Synapse-shaped read frames.

    Safety: the anchor read (param 0x20 link flag) must answer before the sweep
    starts; reads are paced `pace` seconds apart
    instead of being fired as a burst; and the sweep stops after `max_fail`
    consecutive silent params, because a run of silence means the channel
    stopped answering (replug), not that the params are empty."""
    n = hi - lo + 1
    print(f"# sweeping class-08 params 0x{lo:02x}..0x{hi:02x} on {dev} "
          f"({n} reads, {pace:g} s apart)")
    print(f"# frame per read: {bytes(_pro_read_frame(lo))[:12].hex()}")
    if dry_run:
        for p in range(lo, hi + 1):
            print("DRY  %02x  %s" % (p, bytes(_pro_read_frame(p))[:11].hex(" ")))
        return 0
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    seen, fails = {}, 0
    try:
        _pro_drain(fd)
        anchor, buf = _pro_query(fd, PRO_ANCHOR_PARAM, 1.0)
        if anchor is None:
            print("# anchor read (param 0x%02x) got no answer - the dongle is not "
                  "answering.  Replug it and try again; silence to a "
                  "Synapse-identical read is the signature of the wedged state "
                  "(docs/barracudapro.md §7/§8.5)" % PRO_ANCHOR_PARAM)
            return 1
        print("# anchor 0x%02x -> %s" % (PRO_ANCHOR_PARAM, anchor["data"].hex(" ")))
        _record(seen, buf)
        t = time.time()
        for p in range(lo, hi + 1):
            wait = pace - (time.time() - t)
            if wait > 0:
                time.sleep(wait)
            t = time.time()
            reply, buf = _pro_query(fd, p, max(0.3, pace))
            _record(seen, buf)
            if reply is None and p not in seen:
                fails += 1
                if fails >= max_fail:
                    print(f"# {fails} silent reads in a row (last param 0x{p:02x}) "
                          "- stopping; the channel stopped answering, replug if "
                          "the dongle is dead")
                    break
                continue
            fails = 0
            print("  read 0x%02x ..." % p, end="\r")
    finally:
        os.close(fd)
    print("# %d of the %d params asked answered" % (len([p for p in seen if lo <= p <= hi]), n))
    for p in sorted(seen):
        f = seen[p]
        val = "-" if f["value"] is None else "%d (0x%02x)" % (f["value"], f["value"])
        print("  0x%02x value=%-9s data=%s" % (p, val, f["data"].hex(" ")))
    print("# a battery candidate looks like a small value (<= 100 percent) or a "
          "multi-byte payload; add its param to PRO_BATTERY_PARAMS in this file "
          "and ./barracuda_battery.py starts reporting it")
    return 0


def _sweep_cli(dev, argv):
    """`--sweep [LO-HI] [--pace SECONDS] [--dry-run]` argument handling.

    The range is hex, with or without `0x` (`--sweep 12-2c`, `--sweep 0x12`,
    `--sweep 3a-4f`); a single value means just that parameter."""
    def param(txt):
        txt = txt.strip().lower()
        v = int(txt[2:], 16) if txt.startswith("0x") else int(txt, 16)
        if not 0 <= v <= 0xFF:
            sys.exit(f"error: param out of range: {txt}")
        return v

    lo, hi = PRO_SWEEP_RANGE
    i = argv.index("--sweep")
    if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
        a, _, b = argv[i + 1].partition("-")
        lo = param(a)
        hi = param(b) if b else lo
        del argv[i:i + 2]
    else:
        del argv[i]
    if lo > hi:
        lo, hi = hi, lo
    pace = float(argv[argv.index("--pace") + 1]) if "--pace" in argv else 0.25
    if dev is None:
        dev, pid = find_hidraw()
        if dev is None:
            sys.exit("error: Barracuda dongle not found")
        if pid not in PRO_PIDS:
            sys.exit(f"error: {dev} is not a Barracuda Pro (053a) dongle")
    try:
        return _pro_sweep(dev, lo, hi, pace, dry_run="--dry-run" in argv)
    except OSError as e:
        sys.exit(f"error: {e}")


def _pro_dev(dev):
    """Resolve and validate a Barracuda Pro (053a) device path, or sys.exit."""
    if dev is None:
        dev, pid = find_hidraw()
        if dev is None:
            sys.exit("error: Barracuda dongle not found")
    else:
        pid = _hidraw_pid(dev)
    if pid not in PRO_PIDS:
        sys.exit(f"error: {dev} is not a Barracuda Pro (053a) dongle")
    return dev


def _pro_watch(dev, interval=5.0, count=None):
    """Live class-08 reads of 0x2a (status) + 0x21 (percent), paced.

    The verification tool: plug/unplug the charger and power the headset off/on
    while this runs, and watch whether 0x21 tracks a real charge cycle and what
    0x2a does.  Only Synapse-identical class-08 reads are sent, one at a time."""
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    try:
        _pro_drain(fd)
        anchor, _ = _pro_query(fd, PRO_ANCHOR_PARAM, 1.0)
        if anchor is None:
            print("error: link read (param 0x20) got no answer - dongle looks "
                  "wedged; replug and retry (docs/barracudapro.md §9.2)",
                  file=sys.stderr)
            return 1
        print(f"# watching {dev} every {interval:g} s - plug/unplug the charger, "
              "power the headset off/on. Ctrl-C quits.")
        _pro_unlock(fd)   # unlock battery/status reads
        n = 0
        while count is None or n < count:
            st, _ = _pro_query(fd, PRO_STATUS_PARAM, 0.5)
            pct, _ = _pro_query(fd, PRO_BATTERY_PARAMS[0], 0.5)
            sig, _ = _pro_query(fd, PRO_SIGNAL_PARAM, 0.5)
            sv = st["value"] if st else None
            pv = pct["value"] if pct else None
            sg = sig["value"] if sig else None
            status = ("unknown" if sv is None
                      else PRO_STATUS.get(sv, f"0x{sv:02x} (unmapped)"))
            print("%s  status=%-20s  battery=%s%%   (0x2a=%s 0x21=%s  link=%s)"
                  % (time.strftime("%H:%M:%S"), status,
                     pv if pv is not None else "-",
                     ("0x%02x" % sv) if sv is not None else "-",
                     ("0x%02x" % pv) if pv is not None else "-",
                     ("%d" % sg) if sg is not None else "-"))
            n += 1
            if count is not None and n >= count:
                break
            time.sleep(max(0.5, interval))
        return 0
    finally:
        os.close(fd)


def _pro_info(dev):
    """Read the class-08 version/identifier param (0x00) once and print it."""
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    try:
        _pro_drain(fd)
        anchor, _ = _pro_query(fd, PRO_ANCHOR_PARAM, 1.0)
        if anchor is None:
            print("error: link read (param 0x20) got no answer - dongle looks "
                  "wedged; replug and retry", file=sys.stderr)
            return 1
        _pro_unlock(fd)
        reply = None
        for _ in range(3):
            reply, _ = _pro_query(fd, PRO_VERSION_PARAM, 0.5)
            if reply is not None:
                break
        if reply is None:
            print("param 0x00 (version) did not answer - this read is flaky and "
                  "often needs a fuller settings sequence first (see "
                  "docs/barracudapro.md §2)")
            return 1
        data = reply["data"]
        tail = "".join(chr(c) if 32 <= c < 127 else "." for c in data)
        print(f"param 0x00 -> {data.hex(' ')}")
        print(f"  ascii: {tail}")
        return 0
    finally:
        os.close(fd)


def _pro_status_probe(dev, count=4, interval=1.0):
    """Probe the class-0x0e status poll Synapse sends (cmd 02, args e1 01).

    Replies arrive on class 0x01 as `00 03 00 0e 88 ..`.  Synapse sent this 20x
    in the bare-metal capture, so it is a real channel, but it is new to our
    tools: opt-in (--probe-status), paced, replug at hand.  Watch the payload
    while charging/discharging; if it ever wedges the dongle, drop it."""
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    try:
        _pro_drain(fd)
        anchor, _ = _pro_query(fd, PRO_ANCHOR_PARAM, 1.0)
        if anchor is None:
            print("error: link read (param 0x20) got no answer - dongle looks "
                  "wedged; replug and retry", file=sys.stderr)
            return 1
        poll = _frame(0x0E, bytes([0x02, 0xE1, 0x01]), arglen=8)
        print(f"# class 0x0e poll frame: {bytes(poll)[:11].hex(' ')}")
        for _ in range(count):
            os.write(fd, poll)
            buf = b""
            end = time.time() + 0.5
            while time.time() < end:
                if not select.select([fd], [], [], 0.1)[0]:
                    continue
                try:
                    buf += os.read(fd, 64)
                except OSError:
                    break
            frames = _pi_frames(buf)
            if not frames:
                print("  (no reply)")
            for f in frames:
                print("  class 0x%02x seq 0x%02x tick %d data=%s"
                      % (f["class"], f["seq"], f["tick"], f["data"].hex(" ")))
            time.sleep(max(0.5, interval))
        return 0
    finally:
        os.close(fd)


def _pro_unlock(fd):
    """Unlock the battery/status reads with a class-0x0e poll.

    On a cold dongle (e.g. right after a Synapse session) `0x21`/`0x2a` answer
    silence until this poll runs; `0x20` (link) still answers cold.  This is
    the minimal unlock - the `d6` writes are NOT needed for battery/status
    (verified 2026-09-20)."""
    os.write(fd, _frame(0x0E, bytes([0x02, 0xE1, 0x01]), arglen=8))
    time.sleep(0.3)


def _pro_warmup(fd):
    """Run Synapse's open sequence to unlock the class-08 settings channel.

    Without this, only the "always-available" params (0x01/0x20/0x21/0x2a)
    answer a read; the settings params (ANC/EQ/mic-monitor/power-saving/...)
    stay silent.  This is byte-for-byte what Synapse does on connect: two `d6`
    writes, a link read, the class-0x0e poll, then status + battery reads.
    Verified audio-safe 2026-09-20 (see docs/barracudapro.md §9.1)."""
    os.write(fd, _frame(0x08, bytes([0x04, 0xD6, 0x00, 0x01, 0x02]), arglen=8))
    time.sleep(0.2)
    os.write(fd, _frame(0x08, bytes([0x04, 0xD6, 0x00, 0x01, 0x01]), arglen=8))
    time.sleep(0.2)
    _pro_query(fd, PRO_ANCHOR_PARAM, 0.5)               # link flag
    os.write(fd, _frame(0x0E, bytes([0x02, 0xE1, 0x01]), arglen=8))
    time.sleep(0.3)
    _pro_query(fd, PRO_STATUS_PARAM, 0.5)               # status
    _pro_query(fd, PRO_BATTERY_PARAMS[0], 0.5)          # battery


def _pro_features(dev):
    """Warm up the channel, then read every feature-candidate param.

    Prints the confirmed trio (link/status/battery) then each candidate param
    with its value and best-guess label.  Run it before and after toggling a
    feature in Synapse and diff the values to confirm the param->feature map."""
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    try:
        _pro_drain(fd)
        _pro_warmup(fd)

        def val(r):
            return r["value"] if r and r["value"] is not None else None

        link, _ = _pro_query(fd, PRO_ANCHOR_PARAM, 0.5)
        status, _ = _pro_query(fd, PRO_STATUS_PARAM, 0.5)
        pct, _ = _pro_query(fd, PRO_BATTERY_PARAMS[0], 0.5)

        sv = val(status)
        print("link    0x20 = %s" % (val(link) if val(link) is not None else "silent"))
        print("status  0x2a = %s (%s)"
              % (sv if sv is not None else "silent",
                 PRO_STATUS.get(sv, "?") if sv is not None else "silent"))
        print("battery 0x21 = %s %%" % (val(pct) if val(pct) is not None else "silent"))
        print()
        print("feature candidates (labels are best guesses):")
        for param, label in PRO_FEATURES:
            reply, _ = _pro_query(fd, param, 0.4)
            v = val(reply)
            if v is None:
                print("  0x%02x  %-28s = (silent)" % (param, label))
            else:
                print("  0x%02x  %-28s = %d (0x%02x)" % (param, label, v, v))
        return 0
    finally:
        os.close(fd)


def _pro_set(dev, param, value):
    """Write a class-08 param (write side = read param + 0x80) and read it back.

    The write ack reports value 0x00, so we verify by reading the param back.
    Synapse-identical class-08 write, audio-safe (verified 2026-09-20)."""
    fd = os.open(dev, os.O_RDWR | os.O_NONBLOCK)
    try:
        _pro_drain(fd)
        _pro_unlock(fd)
        os.write(fd, _frame(0x08, bytes([0x04, param | 0x80, 0x00, 0x01, value]),
                            arglen=8))
        time.sleep(0.4)
        r, _ = _pro_query(fd, param, 0.5, attempts=2)
        return r["value"] if r and r["value"] is not None else None
    finally:
        os.close(fd)


def _set_anc_cli(dev, argv):
    """`--set-anc off|on|ambient` — write ANC mode (param 0x92), verify by read."""
    i = argv.index("--set-anc")
    mode = argv[i + 1] if i + 1 < len(argv) else None
    if mode not in PRO_ANC_VALUES:
        sys.exit("error: --set-anc needs one of: "
                 + ", ".join(sorted(PRO_ANC_VALUES)))
    got = _pro_set(_pro_dev(dev), 0x12, PRO_ANC_VALUES[mode])
    if got is None:
        sys.exit("error: no answer reading 0x12 back after the write")
    print(f"ANC mode -> {mode} (0x12 = 0x{got:02x})")
    return 0


def _set_cli(dev, argv):
    """`--set 0xPARAM 0xVAL` — write a class-08 param, verify by read."""
    i = argv.index("--set")
    if i + 2 >= len(argv):
        sys.exit("error: --set needs <param> <value> in hex (e.g. --set 12 0a)")
    try:
        param = int(argv[i + 1], 16)
        value = int(argv[i + 2], 16)
    except ValueError:
        sys.exit("error: --set param/value must be hex")
    if not 0 <= param <= 0x7F or not 0 <= value <= 0xFF:
        sys.exit("error: --set param must be 0x00-0x7f, value 0x00-0xff")
    got = _pro_set(_pro_dev(dev), param, value)
    if got is None:
        print(f"wrote 0x{param:02x} = 0x{value:02x} (no readback)")
    else:
        print(f"wrote 0x{param:02x} = 0x{value:02x} -> read back 0x{got:02x}")
    return 0


def _set_sidetone_cli(dev, argv):
    """`--set-sidetone 0-100` — set sidetone level (percent); 0 turns it off.

    Synapse's 0-100 % maps to the dongle's 0-15 scale via `floor(% × 15/100)`;
    this writes 0x18 (on/off) and 0x19 (level) — 0% sets 0x18 = 0 (off), any
    other value sets 0x18 = 1 (on) — then reads both back."""
    i = argv.index("--set-sidetone")
    txt = argv[i + 1] if i + 1 < len(argv) else None
    if txt is None:
        sys.exit("error: --set-sidetone needs a level 0-100 (e.g. --set-sidetone 60)")
    try:
        pct = int(txt)
    except ValueError:
        sys.exit("error: --set-sidetone level must be 0-100")
    if not 0 <= pct <= 100:
        sys.exit("error: --set-sidetone level must be 0-100")
    d = _pro_dev(dev)
    if pct == 0:
        onv = _pro_set(d, 0x18, 0x00)               # 0% -> turn sidetone off
        lvv = _pro_set(d, 0x19, 0x00)               # and zero the level
    else:
        onv = _pro_set(d, 0x18, 0x01)               # turn sidetone on
        lvv = _pro_set(d, 0x19, pct * 15 // 100)    # set level (floor(% × 15/100))
    if onv is None or lvv is None:
        sys.exit("error: no answer reading sidetone back after the write")
    print(f"sidetone -> {pct}%  (0x18={onv}, 0x19={lvv} [0x{lvv:02x}])")
    return 0


def _set_power_save_cli(dev, argv):
    """`--set-power-save 0-60` — set power-saving timeout (minutes); 0 = off.

    The dongle stores the timeout directly in minutes (0x2c: 0 off, 15-60 min).
    Writes 0x2c and reads it back."""
    i = argv.index("--set-power-save")
    txt = argv[i + 1] if i + 1 < len(argv) else None
    if txt is None:
        sys.exit("error: --set-power-save needs minutes 0-60 (0 = off)")
    try:
        mins = int(txt)
    except ValueError:
        sys.exit("error: --set-power-save minutes must be 0-60")
    if not 0 <= mins <= 60:
        sys.exit("error: --set-power-save minutes must be 0-60 (0 = off)")
    d = _pro_dev(dev)
    got = _pro_set(d, 0x2C, mins)
    if got is None:
        sys.exit("error: no answer reading 0x2c back after the write")
    print(f"power saving -> {'off' if mins == 0 else f'{mins} min'}  (0x2c = {got})")
    return 0


def main():
    argv = sys.argv[1:]
    dev = None
    if "--dev" in argv:
        i = argv.index("--dev")
        dev = argv[i + 1]
        del argv[i:i + 2]
    if "--sweep" in argv:
        sys.exit(_sweep_cli(dev, argv))
    if "--info" in argv:
        sys.exit(_pro_info(_pro_dev(dev)))
    if "--features" in argv:
        sys.exit(_pro_features(_pro_dev(dev)))
    if "--set-anc" in argv:
        sys.exit(_set_anc_cli(dev, argv))
    if "--set-sidetone" in argv:
        sys.exit(_set_sidetone_cli(dev, argv))
    if "--set-power-save" in argv:
        sys.exit(_set_power_save_cli(dev, argv))
    if "--set" in argv:
        sys.exit(_set_cli(dev, argv))
    if "--probe-status" in argv:
        sys.exit(_pro_status_probe(_pro_dev(dev)))
    if "--watch" in argv:
        i = argv.index("--watch")
        interval = 5.0
        if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            interval = float(argv[i + 1])
        sys.exit(_pro_watch(_pro_dev(dev), interval))
    console = "--legacy-console-probes" in argv
    if console:
        print("warning: legacy console/class-09 probes are unverified and have "
              "killed audio on this dongle until a replug - see "
              "docs/barracudapro.md §7", file=sys.stderr)
    try:
        s = read_state(dev, console)
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