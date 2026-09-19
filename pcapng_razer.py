#!/usr/bin/env python3
"""
Razer USB capture analyzer (pcapng / USBPcap) — no Wireshark or tshark needed.

Reads a pcapng file written by USBPcap (Wireshark's Windows USB capture, link
type 249; dumpcap's \\\\.\\USBPcap<n> device path), lists the USB devices it
contains (VID/PID + descriptors) and decodes the Barracuda Pro (1532:053a)
"PA"/"PI" frame protocol documented in docs/barracudapro.md §2 and §8.

Usage:
  pcapng_razer.py CAPTURE.pcapng [--summary] [--devices] [--frames] [--dump]
                                 [--vid 1532] [--pid 053a] [--bus 1] [--dev 2]

  --summary  (default) per-device transfer/endpoint overview + timeline
  --devices  decode device/config descriptors (VID:PID, interfaces, endpoints)
  --frames   PA/PI frames, one block per frame, fields decoded (class 08)
  --dump     raw hex + ASCII of every data payload of the selected devices

  --vid/--pid/--bus/--dev restrict everything to matching devices.  --vid/--pid
  need the descriptor to be inside the capture (it is right after enumeration).

Frame envelope (confirmed against Synapse, docs/barracudapro.md §8):

  request   01 80 <len> 50 41 <class> <arglen> <cmd> <args...>
  response  01 80 <len> 50 49 <class> <seq> <tick(3)> <data...>

  <len> = 4 + number of argument bytes after <arglen>/<seq>.  class 0x08
  requests always carry arglen 0x08 (constant — NOT the payload length) and a
  4-5 byte payload: `03 <param> 00 00` read / `04 <param> 00 <vlen> <val>`
  write.  Responses repeat the class, carry a per-response sequence byte, a
  3-byte little-endian timestamp (~800 ticks/s) and `04 00 <param> <kind> 01
  <value>` where kind 0x01 = reply to a request, 0x02 = unsolicited event.

Library:
  from pcapng_razer import load_capture, decode_frame
"""
import struct
import sys

SHB = 0x0A0D0D0A
IDB = 0x00000001
SPB = 0x00000003
EPB = 0x00000006
LINKTYPE_USBPCAP = 249

XTRAN = {0: "iso", 1: "int", 2: "ctrl", 3: "bulk"}
KIND = {0x01: "reply", 0x02: "event"}
CMD = {0x03: "read", 0x04: "write"}


# ---------------------------------------------------------------- pcapng ---

def _options(body, off, endian):
    """pcapng option list -> [(code, value)]."""
    out = []
    while off + 4 <= len(body):
        code, ln = struct.unpack_from(endian + "HH", body, off)
        off += 4
        if code == 0:
            break
        out.append((code, body[off:off + ln]))
        off += (ln + 3) & ~3
    return out


def iter_blocks(path):
    """Yield (block_type, body, endian, offset, total_length) of a pcapng file."""
    d = open(path, "rb").read()
    off, endian, n = 0, "<", len(d)
    while off + 8 <= n:
        btype = struct.unpack_from(endian + "I", d, off)[0]
        if btype == SHB:                       # byte-order magic re-arms endian
            endian = "<" if d[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            btype = struct.unpack_from(endian + "I", d, off)[0]
        blen = struct.unpack_from(endian + "I", d, off + 4)[0]
        if blen < 12 or off + blen > n:
            break
        yield btype, d[off + 8:off + blen - 4], endian, off, blen
        off += blen


def parse_usbpcap(data, endian):
    """USBPcap pseudo-header (27 bytes, 28 for control transfers) -> dict."""
    (hlen,) = struct.unpack_from(endian + "H", data, 0)
    h = {
        "hlen": hlen,
        "irp": struct.unpack_from(endian + "Q", data, 2)[0],
        "status": struct.unpack_from(endian + "I", data, 10)[0],
        "function": struct.unpack_from(endian + "H", data, 14)[0],
        "info": data[16],
        "bus": struct.unpack_from(endian + "H", data, 17)[0],
        "dev": struct.unpack_from(endian + "H", data, 19)[0],
        "ep": data[21],
        "xfer": data[22],
        "dlen": struct.unpack_from(endian + "I", data, 23)[0],
    }
    h["payload"] = data[hlen:]
    return h


def load_capture(path):
    """-> (interfaces, packets, meta).  Packets are USBPcap dicts + 't' (µs)."""
    ifaces, pkts, meta = [], [], {}
    for btype, body, endian, _off, _blen in iter_blocks(path):
        if btype == SHB:
            shb = meta.setdefault("shb", {})
            for code, val in _options(body, 16, endian):
                shb[code] = val.decode("utf-8", "replace")
        elif btype == IDB:
            linktype, _res, snaplen = struct.unpack_from(endian + "HHI", body, 0)
            ifaces.append({"linktype": linktype, "snaplen": snaplen,
                           "opts": _options(body, 8, endian)})
        elif btype in (EPB, SPB):
            t = 0
            if btype == EPB:
                iid, tsh, tsl, cap, _orig = struct.unpack_from(endian + "IIIII", body, 0)
                data = body[20:20 + cap]
                t = (tsh << 32) | tsl
            else:
                iid, data = 0, body[4:]
            if ifaces and ifaces[iid]["linktype"] != LINKTYPE_USBPCAP:
                continue
            h = parse_usbpcap(data, endian)
            h["t"] = t
            pkts.append(h)
    return ifaces, pkts, meta


# ------------------------------------------------------------- descriptors ---

def as_device_descriptor(d):
    """Return descriptor fields if d looks like a USB device descriptor."""
    if len(d) >= 18 and d[0] == 18 and d[1] == 0x01 and 0x0100 <= (d[2] | d[3] << 8) <= 0x0400:
        return {"vid": d[8] | d[9] << 8, "pid": d[10] | d[11] << 8,
                "bcdUSB": d[2] | d[3] << 8, "class": d[4],
                "numconfig": d[17], "imfr": d[14], "iprod": d[15]}
    return None


def decode_config(d):
    """Decode a configuration descriptor into printable rows."""
    rows, i = [], 0
    while i + 2 <= len(d):
        ln, typ = d[i], d[i + 1]
        if ln == 0:
            break
        seg = d[i:i + ln]
        if typ == 2:
            rows.append("CONFIG  wTotalLength=%d interfaces=%d value=%d maxPower=%d mA"
                        % (seg[2] | seg[3] << 8, seg[4], seg[5], seg[8] * 2))
        elif typ == 4:
            rows.append("  IFACE %d alt %d  class=%02x sub=%02x proto=%02x  eps=%d"
                        % (seg[2], seg[3], seg[5], seg[6], seg[7], seg[4]))
        elif typ == 5:
            rows.append("    EP   %02x  %s  maxpkt=%d interval=%d"
                        % (seg[2], {0: "control", 1: "iso", 2: "bulk", 3: "int"}.get(
                            seg[3] & 3, "?"), seg[4] | seg[5] << 8, seg[6]))
        elif typ == 0x21:
            rows.append("    HID  bcdHID=%04x country=%d reportDescLen=%d"
                        % (seg[2] | seg[3] << 8, seg[4], seg[7] | seg[8] << 8))
        elif typ in (0x24, 0x25):              # USB audio class-specific
            rows.append("    CS   subtype=%02x  %s" % (seg[2], seg[3:].hex(" ")))
        i += ln
    return rows


# ------------------------------------------------------------------ frames ---

def decode_frame(d):
    """Decode a 64-byte HID report into a dict, or None if it is not PA/PI."""
    if len(d) < 8 or d[0] != 0x01 or d[1] != 0x80 or d[3:5] not in (b"PA", b"PI"):
        return None
    f = {"dir": "req" if d[3:5] == b"PA" else "rsp", "len": d[2], "class": d[5]}
    end = min(len(d), f["len"] + 3)          # <len> = 4 + bytes after byte 6
    if f["dir"] == "req":
        f["arglen"] = d[6]
        p = bytes(d[7:end])
        f["payload"] = p
        if f["class"] == 0x08 and p:
            f["cmd"] = p[0]
            f["cmdname"] = CMD.get(p[0], "?")
            f["param"] = p[1] if len(p) > 1 else None
            if p[0] == 0x04 and len(p) >= 5:
                f["vlen"] = p[3]
                f["value"] = int.from_bytes(p[4:4 + p[3]], "little")
    else:
        f["seq"] = d[6]
        f["tick"] = d[7] | d[8] << 8 | d[9] << 16       # LE u24, ~800 ticks/s
        p = bytes(d[10:end])
        f["payload"] = p
        if len(p) >= 7 and p[1] == 0x04:
            f["param"] = p[3]
            f["kind"] = p[4]
            f["kindname"] = KIND.get(p[4], "?")
            f["value"] = p[6]
    return f


def fmt_frame(p, t0=0.0):
    """One block of text for a decoded frame (t relative to capture start)."""
    d = p["payload"]
    f = decode_frame(d)
    head = "t=%9.4f bus%d dev%d ep=%3d" % ((p["t"] - t0) / 1e6, p["bus"], p["dev"], p["ep"])
    if not f:
        return head + "  (not a PA/PI frame)"
    txt = "%s  %s len=%02x class=%02x" % (head, "PA->" if f["dir"] == "req" else "PI<-",
                                          f["len"], f["class"])
    if f["dir"] == "req":
        txt += " arglen=%02x" % f["arglen"]
        if "cmd" in f:
            txt += " cmd=%02x(%s) param=%02x" % (f["cmd"], f["cmdname"], f["param"])
            if f["cmd"] == 0x04:
                txt += " value=%d(0x%02x)" % (f["value"], f["value"])
    else:
        txt += " seq=%02x tick=%d" % (f["seq"], f["tick"])
        if "param" in f:
            txt += " param=%02x kind=%02x(%s) value=%d(0x%02x)" % (
                f["param"], f["kind"], f["kindname"], f["value"], f["value"])
    return txt + "\n           " + d[:18].hex(" ")


# -------------------------------------------------------------------- cli ---

def ascii_(d):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in d)


def main():
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        sys.exit("usage: pcapng_razer.py CAPTURE.pcapng"
                 " [--summary] [--devices] [--frames] [--dump]"
                 " [--vid HEX] [--pid HEX] [--bus N] [--dev N]")
    path = argv.pop(0)
    filters = {}
    for name in ("vid", "pid", "bus", "dev"):
        if "--" + name in argv:
            i = argv.index("--" + name)
            filters[name] = int(argv[i + 1], 16 if name in ("vid", "pid") else 10)
            del argv[i:i + 2]

    try:
        ifaces, pkts, meta = load_capture(path)
    except OSError as e:
        sys.exit("error: cannot read %s: %s" % (path, e))
    if not pkts:
        sys.exit("error: no USBPcap packets in %s" % path)

    # identify devices from the (re-)enumeration descriptors inside the capture
    ids, configs = {}, {}
    for p in pkts:
        d = p["payload"]
        dd = as_device_descriptor(d)
        if dd:
            ids[(p["bus"], p["dev"])] = dd
        elif len(d) >= 9 and d[0] >= 9 and d[1] == 2 and (d[2] | d[3] << 8) == len(d):
            configs[(p["bus"], p["dev"])] = decode_config(d)

    def match(key):
        """Does this (bus, dev) key pass the --bus/--dev/--vid/--pid filters?"""
        if "bus" in filters and key[0] != filters["bus"]:
            return False
        if "dev" in filters and key[1] != filters["dev"]:
            return False
        dd = ids.get(key)
        if "vid" in filters and (dd is None or dd["vid"] != filters["vid"]):
            return False
        if "pid" in filters and (dd is None or dd["pid"] != filters["pid"]):
            return False
        return True

    def selected(p):
        return match((p["bus"], p["dev"]))

    t0 = min(p["t"] for p in pkts if p["t"])
    span = (max(p["t"] for p in pkts) - t0) / 1e6
    print("capture : %s" % path)
    shb = meta.get("shb", {})
    for code, name in ((2, "hardware"), (3, "os"), (4, "app")):
        if code in shb:
            print("          %-8s %s" % (name, shb[code]))
    print("          %.3f s, %d packets, %d interface(s), linktype %s"
          % (span, len(pkts), len(ifaces), ifaces[0]["linktype"] if ifaces else "?"))

    if not ({"--devices", "--frames", "--dump"} & set(argv)):
        print("\n=== devices ===")
        for key in sorted({(p["bus"], p["dev"]) for p in pkts}):
            dd = ids.get(key)
            name = "unknown (no descriptor in capture)"
            if dd:
                name = "%04x:%04x  bcdUSB %04x  class %02x" % (
                    dd["vid"], dd["pid"], dd["bcdUSB"], dd["class"])
            sub = [p for p in pkts if (p["bus"], p["dev"]) == key]
            kinds = {}
            for p in sub:
                k = (XTRAN.get(p["xfer"], p["xfer"]), p["ep"])
                kinds[k] = kinds.get(k, 0) + 1
            t = [p["t"] for p in sub if p["t"]]
            print("bus%d dev%d  %s" % (key[0], key[1], name))
            print("          %d packets: %s" % (len(sub), ", ".join(
                "%s ep%02x x%d" % (k[0], k[1], v) for k, v in sorted(kinds.items()))))
            if t:
                print("          active %.3f .. %.3f s"
                      % ((min(t) - t0) / 1e6, (max(t) - t0) / 1e6))

    if "--devices" in argv:
        for key in sorted(configs):
            if not match(key):
                continue
            dd = ids.get(key)
            print("\n=== bus%d dev%d descriptors ===" % key)
            if dd:
                print("DEVICE  %04x:%04x  bcdUSB=%04x class=%02x configs=%d"
                      % (dd["vid"], dd["pid"], dd["bcdUSB"], dd["class"], dd["numconfig"]))
            for row in configs[key]:
                print(row)

    if "--frames" in argv:
        print("\n=== PA/PI frames ===")
        n = 0
        for p in pkts:
            if p["dlen"] and selected(p) and decode_frame(p["payload"]):
                n += 1
                print(fmt_frame(p, t0))
        print("(%d frames)" % n)

    if "--dump" in argv:
        print("\n=== payload dump ===")
        for p in pkts:
            if not p["dlen"] or not selected(p):
                continue
            d = p["payload"]
            print("t=%9.4f bus%d dev%d ep=%3d %s len=%d"
                  % ((p["t"] - t0) / 1e6, p["bus"], p["dev"], p["ep"],
                     XTRAN.get(p["xfer"], p["xfer"]), len(d)))
            for i in range(0, min(len(d), 64), 16):
                print("    %04x  %-47s  |%s|"
                      % (i, d[i:i + 16].hex(" "), ascii_(d[i:i + 16])))


if __name__ == "__main__":
    main()
