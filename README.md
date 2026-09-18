# Barracuda X Battery Meter — protocol notes & tools

Battery level of the **Razer Barracuda X** (2.4 GHz USB dongle, `VID:PID 1532:0536`),
read directly over HID on Linux. Reverse-engineered from sibling-device projects
(Razer Nari dongle family) and validated live on this machine (Fedora, 2026-09-18).

## Usage

```bash
./barracuda_battery.py           # one shot:  Battery: 80% (4128 mV, charging)
./barracuda_battery.py --json    # machine readable (nice for a tray app subprocess)
./barracuda_battery.py -v        # + raw state hex
./barracuda-watch 5              # live view, refresh every 5 s (default), Ctrl-C quits
```

The hidraw node is auto-detected by `HID_ID 0003:1532:0536` (also accepts the
Barracuda X variants `0552` / `0574`), so it survives replugs and hidraw renumbering.
`~/.local/bin/barracuda-battery` is a symlink to `barracuda_battery.py`.

## How the protocol works

The dongle exposes one vendor HID interface (USB interface 3). Its report
descriptor defines numbered reports; everything interesting happens on the
**64-byte vendor feature report with report ID `0xFF`** (usage page `0xFF00`).
The dongle keeps a *cached state blob*; the host populates it with a SET_REPORT
query, then reads it back with GET_REPORT (this 4-frame SET/GET cycle is exactly
what Razer Synapse repeats every few seconds on Windows).

```
SET_REPORT  bmRequestType 0x21, bRequest 0x09 (SET_REPORT), wValue 0x03FF, wLength 64
payload:    ff 0a 00 fd 04 12 f1 02 05 00 00 … (55 zero bytes)

GET_REPORT  bmRequestType 0xA1, bRequest 0x01 (GET_REPORT),  wValue 0x03FF, wLength 64
response:   ff 0f 05 fe 12 04 1f 08 05 … (64 bytes, see layout)
```

On hidraw this is simply `HIDIOCSFEATURE(64)` / `HIDIOCGFEATURE(64)` with the
buffer's first byte = `0xFF` (the report ID doubles as the first payload byte
on the wire). No kernel driver, no Synapse, no root needed on this box
(node was mode 0666; openrazer's udev rules provide the plugdev fallback).

### State layout (verified)

| offset | type    | meaning                                                        |
|--------|---------|----------------------------------------------------------------|
| `[0]`  | u8      | `0xFF` report-id echo                                          |
| `[1..8]`|        | `0f 05 fe 12 04 1f 08 05` — constant header in all captures    |
| `[9]`  | u8      | **charge status**: `0x03` discharging · `0x05` charging · `0x06` fully charged |
| `[10..11]` |     | `05 01` here (`05 02` on the Nari — model-related)             |
| `[12..13]` | u16 BE | **battery voltage in millivolts** (primary signal)          |
| `[14]` | u8      | **battery percent**, firmware-reported (sanity check)          |
| `[15..63]` |     | zero (the Nari variant packs a version string + TLV payload here) |

Example (live, this PC):

```
ff 0f 05 fe 12 04 1f 08 05 05 03 05 10 20 50 00 …
                             │           │  │
                     [9]=05 charging  4128 mV  80%
```

### Validation performed

* Live transition captured mid-session: `discharging / 3784 mV` → (charger
  plugged in) → `charging / 4128 mV`, percent stable at 80 — fields flip/rise
  exactly as documented for the Nari family.
* Cross-checks agree: ~3.78 V ≈ 78–82% on a Li-ion curve ≈ byte `[14]` = 80.
* Nari reference capture from RazerNariBatteryLevel decodes with the same
  offsets: `…0d e0 1e…` = 0x0DE0 = 3552 mV, `[14]` = 0x1e = 30%.

## Gotchas (read before building a tray)

* **Do not** use the 90-byte Synapse/`razer_report` protocol (command class
  `0x07`, battery `0x80`/`0x84`, transaction `0x1F`) — that one works on the
  *Barracuda* `1532:053C` (OpenRazer PR #2373) but this `0536` dongle **STALLs**
  it (`HIDIOCSFEATURE` → EPIPE). The 64-byte Nari-style protocol is the only path.
* No interrupt-IN telemetry in idle: the dongle pushes nothing on its IN
  endpoint without the SET query — state is strictly pull-based (SET then GET).
* The GET returns the *cache*: always SET before GET. Back-to-back GETs return
  the same bytes.
* If the cache is empty (fresh plug, headset off) the blob reads `ff 01 00 …`
  and `[14]` = 0 — don't report that as "0% battery"; retry after a query.
  The reader raises instead when `[14]` > 100.
* Polling the query is benign (Synapse does it every few seconds); 5–10 s
  intervals are plenty. NariMeter derives % from the mV reading and uses `[14]`
  only as a sanity check — you can do the same and calibrate mV↔% bounds over a
  full charge cycle.
* Charge-status values `0x06` (full) / others are taken from the Nari docs;
  only `0x03` and `0x05` were observed live so far.

## Sources

* github.com/Modzeleczek/RazerNariBatteryLevel — Nari dongle SET/GET cycle + payload (`ff 0a 00 fd 04 12 f1 02 05`), C/libusb
* github.com/indina853/NariMeter — field table (`[9]` status, `[12:13]` mV BE, `[14]` percent), Windows tray app
* openrazer/openrazer PR #2373 — why the 053C's 90-byte protocol exists (and why it doesn't apply here)
* openrazer issues #2295 / #2649 / #2704 — Barracuda X family device IDs (0536 / 0552 / 0574)