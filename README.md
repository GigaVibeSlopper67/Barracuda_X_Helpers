# Barracuda X / Pro Battery Meter — protocol notes & tools

Battery level of the **Razer Barracuda X** (2.4 GHz USB dongle, `VID:PID 1532:0536`),
read directly over HID on Linux. Reverse-engineered from sibling-device projects
(Razer Nari dongle family) and validated live on this machine (Fedora,
2026-09-18/19 — discharge, charge and fully-charged states all observed).

The **Barracuda Pro 2.4** dongle (`1532:053a`) speaks a different, newer protocol
("PA" frames over the interrupt endpoints) — see
[Barracuda Pro 2.4 (053a) — second protocol](#barracuda-pro-24-1532053a--second-protocol)
below. `barracuda_battery.py` auto-detects which dongle is present and picks the
right reader.

## Usage

```bash
./barracuda_battery.py           # one shot:  Battery: 80% (4128 mV, charging)
./barracuda_battery.py --json    # machine readable (nice for a tray app subprocess)
./barracuda_battery.py -v        # + raw state hex
./barracuda-watch 5              # live view, refresh every 5 s (default), Ctrl-C quits
```

The hidraw node is auto-detected by `HID_ID 0003:1532:0536` (also accepts the
Barracuda X variants `0552` / `0574` and the Barracuda Pro `053a`), so it survives
replugs and hidraw renumbering.
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
| `[10..11]` |     | varies with state — `03 05` charging · `05 06` fully charged (Nari: `05 01`/`05 02`) |
| `[12..13]` | u16 BE | **battery voltage in millivolts** (primary signal)          |
| `[14]` | u8      | **battery percent**, firmware-reported (sanity check)          |
| `[15..63]` |     | zero (the Nari variant packs a version string + TLV payload here) |

Example (live, this PC) — charging at 80 %:

```
ff 0f 05 fe 12 04 1f 08 05 05 03 05 10 20 50 00 …
                             │           │  │
                     [9]=05 charging  4128 mV  80%
```

and fully charged (2026-09-19) — note the flat 4200 mV and `[10..11]` = `05 06`:

```
ff 0f 05 fe 12 04 1f 08 05 06 05 06 10 68 64 00 …
                             │           │  │
                     [9]=06 fully charged  4200 mV  100%
```

### Validation performed

* Live transition captured mid-session: `discharging / 3784 mV` → (charger
  plugged in) → `charging / 4128 mV`, percent stable at 80 — fields flip/rise
  exactly as documented for the Nari family.
* Cross-checks agree: ~3.78 V ≈ 78–82% on a Li-ion curve ≈ byte `[14]` = 80.
* Nari reference capture from RazerNariBatteryLevel decodes with the same
  offsets: `…0d e0 1e…` = 0x0DE0 = 3552 mV, `[14]` = 0x1e = 30%.
* Fully-charged end state confirmed (2026-09-19, charge cycle run to the end):
  `[9]` = `0x06` exactly as assumed from the Nari docs, `[14]` = `0x64` = 100 %,
  and the voltage field pinned at a flat **4200 mV** (`0x1068` — the nominal
  4.2 V Li-ion full voltage; a steady reported value, not a live cell
  measurement). While charging, the same field varies and can read higher.
  Capture: `… 05 06 05 06 10 68 64 00 …` → fully charged · 4200 mV · 100 %.
* Bytes `[10..11]` look like a `[previous][current]` status pair: the
  discharging→charging capture reads `03 05`, charging→fully-charged reads
  `05 06` — `[11]` always mirrors `[9]`.

## Barracuda Pro 2.4 (`1532:053a`) — second protocol

The **Barracuda Pro 2.4** dongle (`1532:053a`, "Macronix Razer Barracuda Pro 2.4",
USB interface 3, EP 3 OUT / EP 4 IN) does **not** speak the 0xFF feature-report
protocol above — every feature-report transfer STALLs (EPIPE).  It speaks a
newer "PA" frame protocol over the interrupt endpoints instead (report id 0x01,
64-byte packets):

    request:  01 80 <len> 50 41 <class> <arglen> <cmd> <args..>
    response: 01 80 <len> 50 49 <class> <seq> <tick3> <data..>

(`50 41` = "PA" request tag, `50 49` = "PI" response tag, `<len>` = 4 + the
argument bytes after `<arglen>`/`<seq>`.)  For class `0x08` the `<arglen>` byte
is a constant `08` — **not** the payload length (reads carry 4 bytes, writes
5) — and a response carries a per-response sequence byte plus a 3-byte
little-endian device timestamp (~800 ticks/s).  A Synapse USBPcap capture
(2026-09-20; `docs/barracudapro.md` §8, decoded with `./pcapng_razer.py
--frames`) confirmed all of this: Synapse gets its reply 10.7–21.4 ms after each
request, with two IN URBs kept pending and **no flush frame** — the "queued
until the next write" behaviour we saw on Linux is most likely an artifact of
how our probes read (and of a wedged parser after a malformed frame).

* class `0x08` = Synapse settings channel: read `03 <param> 00 00`, write
  `04 <param> 00 <len> <val>`, multi-write `0d <param> 00 <n> <vals>…`.
  Known params (from Synapse captures, openrazer issue #2009): ANC *mode*
  `0x12/0x92` (`0x00` off · `0x0a` on · `0xff` ambient; the 1–10 *level* is
  software/transient), EQ `0x1e/0x96/0x97`, sidetone `0x18` (on/off) + `0x19`
  (level), power-saving `0x2c/0xac` (timeout in minutes: 0 off, 15–60).  **Not on USB** (software DSP in Synapse — the
  fourth capture shows zero frames when toggled): THX↔Stereo, Bass Boost, Mic
  Noise Cancellation, Volume.
  The 2026-09-20 capture exercised `0x12`/`0x92` and `0x2c`/`0xac`: the write
  side is always the read param + `0x80`, the written value reads back on the
  next poll, and a write **ack reports `value = 00`**, not the written value.
  Unknown params answer silence; the console channel (below) answers
  `"<cmd> is not a command"`.

  **Battery is class-08 `param 0x21`** (`03 21 00 00`): the bare-metal capture
  (2026-09-20) read `0x5d` = 93 exactly when Synapse's UI showed 93 %.  Read
  immediately before it, `param 0x2a` is the charge state: `0x00` = on battery,
  `0x01` = charging (verified by plugging/unplugging the charger).  `param 0x00`
  returns a version/identifier string (ends `...IN`).  `read_state()` reads
  `0x2a` + `0x21` and reports percent + charge state directly.
* class `0x02` = line-oriented firmware console.  In its "append mode"
  (observed once) a payload of `\x08\x08\x08` + `bat\r\n` erases the frame
  prefix from the console line buffer and runs the **`bat`** command; the
  reply is a status frame (type 09):

      01 00 26 00 09 88 <36-byte payload>

      payload[4..7]   u32 charge state (0x07 observed while charging)
      payload[8..11]  u32 charge level in percent (0x56 = 86 observed)
      payload[12..]   u32 ms-timers (one matched the dongle uptime exactly)

  The console is state-dependent and is the fragile part of this protocol:

  - fresh after a replug it runs in **data mode**: the payload is consumed
    as data, payload text never reaches the command line, and probes are
    answered within a second with e.g. "P is not a valid command";
  - a frame whose `arglen` is absurdly large **wedges** the console
    completely silent (all later frames are eaten as data) until the next
    replug — note `arglen` is *not* the payload length (class-08 Synapse
    traffic runs `arglen 08` with 4-5 byte payloads); what broke the dongle
    was `arglen 0x40`, larger than the whole frame;
  - in append mode `bat`/`adc` are accepted silently and produce the blob.

  What switches the console into append mode is unknown.  Console replies
  can queue for 2-13 s and are flushed by the next write.  `read_state()`
  probes the `bat` line, a class-09 `cmd 04` query and the `bat` line again
  with a longer window, scanning all replies for the blob marker
  `26 00 09 88`; console errors are reported verbatim.  Full write-up with
  evidence tables: `docs/barracudapro.md`.

  **Pro probing used to hang the dongle** (audio stopped until a USB replug),
  and the class-02/class-09 probes are the prime suspect — Synapse never sends
  them.  They are opt-in now (`--legacy-console-probes`); the default path only
  sends class-08 reads that are byte-identical to Synapse's own traffic, and the
  first frame is the link-flag read (param `0x20`) that decides whether the dongle is
  answering at all:

  ```bash
  ./barracuda_battery.py                          # battery percent (param 0x21)
  ./barracuda_battery.py --watch [SECONDS]        # map 0x2a/0x21 live
  ./barracuda_battery.py --info                   # version string (param 0x00)
  ./barracuda_battery.py --probe-status           # class-0x0e poll (opt-in)
  ./barracuda_battery.py --sweep 12               # is the channel alive?
  ./barracuda_battery.py --sweep                  # hunt for a battery param
  ./barracuda_battery.py --legacy-console-probes  # the old, risky probes
  ```

  Silence to that anchor read is the signature of the wedged state (audio dead,
  device still enumerated): replug the dongle.  Battery is class-08 `param 0x21`
  (percent, verified against Synapse) with status on `0x2a`; `--watch` maps the
  status byte, `--info` reads the version, `--probe-status` probes the class-0x0e
  poll channel.

  **Next round, step by step — including what to capture in Windows and what to
  look for: [`docs/barracudapro-runbook.md`](docs/barracudapro-runbook.md).**

Captures can be analysed without Wireshark (`pcaps/` is git-ignored):

```bash
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng'                       # bus overview
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng' --devices             # descriptors
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng' --frames --vid 1532 --pid 053a
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng' \
    --extract small.pcapng --pid 053a --no-iso                       # shrink to share
```

Export pitfall: in Wireshark, `usb.idVendor`/`usb.idProduct` exist only in the
device descriptor, so a display filter on them + "export displayed packets"
gives a 2-packet file with no traffic.  Filter on `usb.bus_id` /
`usb.device_address` instead (or export everything and use `--extract`).

Other classes seen answering: `0x04`/`0x05`/`0x07`/`0x09`/`0x0a` (short
diagnostic replies, contents not yet decoded); unknown console commands
answer `"<x> is not a valid command"`, other unknown frames answer silence.
`barracuda_battery.py` implements the probe sequence and parses
percent/state from the blob; the state/percent semantics still deserve a
flip test (unplug the charger and compare consecutive blobs).

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
  full charge cycle (top of the range now measured: fully charged = constant
  4200 mV ↔ 100 %).
* Charge-status values come from the Nari docs; as of 2026-09-19 all three real
  states are confirmed live on this dongle (`0x03` discharging, `0x05` charging,
  `0x06` fully charged). `0x00` shows up only in the empty-cache case above.
* The 4200 mV in the fully-charged state is a reported constant (rock-steady
  across polls), not a live cell measurement — and while charging the reading
  can be higher. Don't treat 4200 mV as a range ceiling or detect "full" from a
  mV threshold; use status `0x06` as the reliable end-of-charge signal.

## KDE / desktop tray integration

`barracuda-tray` shows the headset battery as a system-tray icon. Qt implements
the **StatusNotifierItem** protocol on Linux, which KDE Plasma 5/6 renders
natively (GNOME via an extension, sway, Hyprland … also work), and it posts
desktop notifications on state transitions: `< 20 %` low, `< 10 %` critical
(once per discharge, re-armed when charging or above 25 %), "fully charged",
and dongle un/re-plug. The empty-cache blob (`ff 01 00 …`, headset off) is
treated as *unknown* and never reported as 0 %.

```bash
sudo dnf install python3-pyqt6          # Fedora; libnotify is already installed
./barracuda-tray                        # tray icon, 30 s poll
./barracuda-tray --interval 10 --debug  # faster poll + stdout logging
./barracuda-tray --test-notify          # fire all notification kinds once, exit
./barracuda-tray --selftest             # verify icon/notify logic (no hardware, no Qt)
```

Install (pick a launcher, and optionally the udev rule):

```bash
# udev: read access without openrazer (logind uaccess for the active seat user)
sudo cp install/70-barracuda.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger

# make it available on PATH (same convention as the barracuda-battery symlink)
ln -s "$(pwd)/barracuda-tray" ~/.local/bin/barracuda-tray

# launch at login, option A: XDG autostart
cp install/barracuda-tray.desktop ~/.config/autostart/

# option B: systemd user unit (auto-restart, journalctl --user -u barracuda-tray)
cp install/barracuda-tray.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now barracuda-tray
```

Tray menu: current state (read-only), *Refresh now*, *Watch live in Konsole…*
(runs `barracuda-watch`), *Notifications* toggle, *About*, *Quit*. A single
click posts the current state as a transient notification.

## Sources

* github.com/Modzeleczek/RazerNariBatteryLevel — Nari dongle SET/GET cycle + payload (`ff 0a 00 fd 04 12 f1 02 05`), C/libusb
* github.com/indina853/NariMeter — field table (`[9]` status, `[12:13]` mV BE, `[14]` percent), Windows tray app
* openrazer/openrazer PR #2373 — why the 053C's 90-byte protocol exists (and why it doesn't apply here)
* openrazer issues #2295 / #2649 / #2704 — Barracuda X family device IDs (0536 / 0552 / 0574)
* openrazer issue #2009 — Barracuda Pro support request; z3ntu's Synapse Wireshark
  captures (re-uploaded 2026-07) are the source of the PA/PI frame protocol above
* openrazer PR #2899 — BlackShark V3 X dongle console protocol (sibling "recent
  audio device" firmware; battery via feature report 0x07, class 07 / cmd 80)