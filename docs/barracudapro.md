Barracuda Pro Data:

lsusb:
Bus 007 Device 004: ID 1532:053a Razer USA, Ltd Razer Barracuda Pro 2.4
Features:
- ANC Modes: ANC ON - Ambient - OFF OFF
- Mute Button (Probably mechanical, I don't know)
- Volume: Clicky wheel endless scroll, gives audio beep for lowest and highest point

Curent State in the beginning:
- ANC ON
- Max Vol
- Unknown Charge
- Plugged in for charging
- Pairedvia 2.4 GHZ Dongle

---

# Reverse-engineering findings — Barracuda Pro 2.4 dongle (1532:053a)

Session of 2026-09-18/19. All findings below were measured live on this dongle
unless marked "from Synapse captures" (z3ntu's Wireshark uploads in
openrazer issue #2009).

## 1. Device / transport

* `lsusb`: `1532:053a Razer USA, Ltd Razer Barracuda Pro 2.4`, manufacturer
  string "Macronix Razer Barracuda Pro 2.4" (same Macronix dongle generation
  as the Barracuda X / Razer Nari family).
* USB interface 3 is the vendor control interface; EP 3 OUT / EP 4 IN,
  64-byte interrupt transfers, HID report id 0x01, 90 ms polling.
* HID report descriptor (103 bytes): vendor usage page 0xFF00, report 0x01 =
  63-byte Input + 63-byte Output, report 0x02 = Consumer Control. **No feature
  reports are declared** — and indeed every HID feature control transfer
  (report id 0x00/0x01/0x02/0x07/0xFF) STALLs with EPIPE. The Barracuda X
  protocol (0xFF feature report) and the BlackShark V3 X protocol (openrazer
  PR #2899, feature 0x07 / class 07 / cmd 80) both do not work.
* hidraw node is world-readable; the node number changes on replug
  (hidraw12 -> hidraw23 -> ...), so always re-enumerate via
  `/sys/class/hidraw/*/device/uevent` (`HID_ID 0003:1532:053A`).

## 2. "PA" frame protocol (interrupt IN/OUT, report id 0x01)

```
request : 01 80 <len> 50 41 <class> <arglen> <payload...>   ("PA" = 50 41)
response: 01 80 <len> 50 49 01 c0 <seq2> <ctr2> <data...>   ("PI" = 50 49)
```

* `<len>` = 4 + payload length. `<arglen>` = payload length.
* `<seq2>` increments per response; `<ctr2>` per request.
* Latency: settings reads answer in 13-38 ms.
* The dongle is strictly pull-based: 92 s of passive listening produced zero
  frames. It pushes only on state changes, e.g. replug produces a
  class-08 param 0x20 "flag 02, val 01" link event.

### Classes

* `0x08` — Synapse settings channel (works reliably, even on a fresh dongle):
  * read  : `03 <param> 00 <pad..>`
  * write : `04 <param> 00 <len> <val..>`
  * multi : `0d <param> 00 <n> <vals..>`
  * known params (from Synapse captures): ANC `0x12`/`0x92`,
    EQ `0x1e`/`0x96`/`0x97`, mic monitor `0x18`/`0x98`/`0x99`,
    power-saving `0x2c`/`0xac`, link flag `0x20`.
  * A sweep of all 256 read params found only `0x01` (answers 01) and `0x20`
    (link flag) — **no battery parameter exists on class 0x08**.
* `0x02` — line-oriented firmware console (see §3).
* `0x09` — status channel; a `cmd 04` query returned the battery blob once
  (see §4).
* `0x04/0x05/0x07/0x0a` — short diagnostic replies, not decoded.

## 3. The firmware console (class 0x02)

The console is a line editor fed by the *frame text* (`PA` + class + arglen +
payload). Its behavior is **mode- and state-dependent**, which made it the
hardest part to pin down:

### Fresh console (right after dongle replug) — "data mode"

* The line buffer is built from the frame header: `P A <class> <arglen>`.
  The payload is consumed as `<arglen>` bytes of *data*: `\x08` in the
  payload acts as backspace **erasing from the header**, payload *text is
  never appended to the line*, `\r\n` in the payload submits the line, and a
  complete data block without `\r\n` submits it too.
* Measured evidence (fresh console, response latency 0.6 s, no flush needed):

  | probe (class 02 unless noted) | console line | reply |
  |---|---|---|
  | payload `08 08 08 "bat" 0d 0a` (3x BS, arglen 08) | `P` | "P is not a valid command" |
  | payload `08 08 08 08 "bat" 0d 0a` (4x BS, arglen 09) | *(empty)* | " is not a valid command" |
  | class 09, arglen 08, payload `04 00..` | `PA` | "PA is not a valid command" |
  | earlier: arglen 0x1d, no payload | `PA 02` | "PA 02 is not a valid command" |

  (arglen `0x08` doubles as a backspace: for the class-09 probe it erased the
  class byte, leaving line "PA".)
* In data mode the `bat` command **cannot be reached** — the payload text
  never becomes the line.

### Wedged console — "data-eating mode"

A frame whose `arglen` exceeds its payload length makes the parser wait for
the missing data bytes and swallow **all subsequent frames** as data: the
console goes completely silent (no echo, no error — and nothing reaches the
class-08/09 handlers either). This is the "console wedges after bursts of
traffic" mechanism. **Only a dongle replug clears it.** (Measured: arglen
0x40 with a 1-byte payload silenced the console; two follow-up frames
produced zero bytes of output.)

### Append mode (observed once, mid-session)

Earlier in the session — after long traffic bursts, before any replug — the
console *did* append payload text to the line: probe lines answered
`"<line> is not a valid command"`, and `bat` (sent as payload
`08 08 08 "bat" 0d 0a`, the backspaces erasing the header residue) was
**accepted silently** and produced the battery blob (§4). `adc` was also
accepted silently. **What switches the console into append mode is still
unknown** (candidates: sustained traffic volume, specific earlier frames,
headset link state, uptime). This is the main open question.

### Reply plumbing

* In append/wedged states replies are QUEUED and only flushed by the next
  write frame — observed lags 2-13 s. In fresh data mode replies are
  immediate (~0.6 s).
* Never run a background listener on the IN endpoint while probing: it
  steals the responses.

## 4. The battery blob

`bat` (append mode) and a class-09 `cmd 04` query (once, wedged state) both
produced this status frame:

```
01 00 26 00 09 88 <36-byte payload>
     ^^ len      ^^ type 09, cmd/seq 88

payload[0..3]   00 00 00 00   unused / low-battery flag?
payload[4..7]   u32 charge state (0x07 observed while charging)
payload[8..11]  u32 charge level in percent (0x56 = 86 observed)
payload[12..]   u32 millisecond timers; one field matched the
                dongle uptime exactly (~50 min at capture time)
```

Only one blob was ever captured (86 %, charging). The charge-state codes
beyond 0x07 and the exact timer semantics are unmapped — unplug the charger
while querying to flip the state code. Charger events themselves produce no
traffic; only the console/class-09 query reads the battery.

## 5. What the tools do today

* `barracuda_battery.py` auto-detects the PID and dispatches:
  X family -> 0xFF feature report (percent [14], mV [12:14] BE, status [9]);
  Pro (053a) -> probes the console `bat` line, a class-09 `cmd 04` query and
  the `bat` line again with a longer window, scanning replies for the
  `26 00 09 88` blob marker; millivolts is `None` on the Pro. If the console
  answers with command errors instead, the reader reports them — that means
  data mode (see §3) and the blob is not reachable without the append mode.
* `barracuda-watch` / `barracuda-tray` render `millivolts=None` gracefully.
* `install/70-barracuda.rules` grants uaccess to 053a.

## 6. Open questions / next steps

1. **Console append-mode trigger** — the key unknown for a reliable reader.
   Try: sustained console traffic, headset link up/down, uptime.
2. Charge-state codes: only 0x07 (charging) mapped. Capture discharging /
   fully-charged blobs (query `bat`/class-09 after unplugging the charger).
3. Blob timer fields and payload[0..3] semantics.
4. Classes 0x04/0x05/0x07/0x0a diagnostic replies — probably not needed
   for battery, but they may contain richer status.

## 7. Incident: a probe burst hung the dongle (2026-09-19)

During the first probing session the dongle stopped working entirely:
**audio output died and only a USB replug brought it back** (the hidraw
console went silent at the same time). The prime suspect is our own traffic —
that session had just sent a burst of 256 class-08 parameter reads and
several experimental class-02 console frames, and one later probe
deliberately used an `arglen` overrun (`0x40` with a 1-byte payload), which
wedges the frame parser (§3). A parser wedge alone should not kill audio, so
the firmware most likely asserts/hangs and the whole dongle — including its
USB audio functions — stays dead until it is re-enumerated. Correlation, not
proof, but the safe conclusion is that this protocol is fragile:

* **Never send an `arglen` that differs from the real payload length**
  (`barracuda_battery.py::_frame` now derives both from the payload and
  rejects oversized payloads).
* Avoid bursts and polling loops: `barracuda-watch` (5 s default) and
  `barracuda-tray` (30 s) each fire the full 3-frame Pro probe set every
  tick — **do not run them against a 053a dongle** until the frame grammar
  is confirmed.
* The reader's class-09 `cmd 04` query is an **invented** command (7 zero
  argument bytes): plausibly legal, but unverified.
* Keep a replug handy — it has always restored the dongle so far.

### Next step: capture Synapse on Windows

OpenRazer has no Barracuda (053a) support at all (its headset drivers cover
only the older Kraken family, which speak a different "control message"
protocol), so there is no reference implementation to copy. A USBPcap capture
of Synapse is therefore the recommended next step:

1. Install Wireshark on Windows **with the USBPcap component**.
2. Capture on the root hub hosting the dongle; open Synapse and let it poll
   for ~60 s while you (a) open the battery/headset panel, (b) unplug and
   replug the charger (charge-state change) and (c) power the headset off
   and on.
3. Keep only the dongle's traffic
   (`usb.idVendor == 0x1532 && usb.idProduct == 0x053a`) and export the
   displayed packets to `.pcapng`.
4. What to look for: interrupt transfers on interface 3 (EP 3 OUT / EP 4 IN)
   carrying `01 80 <len> 50 41 …`; whether `<len>` always equals the payload
   length; which class carries the battery poll (0x02 console / 0x08 param /
   0x09 status) and its exact command bytes; the poll cadence; and whether
   Synapse sends anything after a query to flush the reply.