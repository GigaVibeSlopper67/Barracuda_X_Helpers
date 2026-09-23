Barracuda Pro Data:

lsusb:
Bus 007 Device 004: ID 1532:053a Razer USA, Ltd Razer Barracuda Pro 2.4
Features:
- ANC Modes: ANC ON - Ambient - ANC OFF
- Mute Button (Probably mechanical, I don't know)
- Volume: Clicky wheel endless scroll, gives audio beep for lowest and highest point

Interesting Razer Synapse Features:
- Mic Monitoring (Side Tone)
- Switch between Stereo and THX spatial audio
- ANC Values from 1 to 10
- Bass Boost ON/OFF and 100 steps
- Mic Noise cancellation
- Power Saving ON/OFF and set the turnoff between 15 and 60 Minutes

Features that might not be needed because they culd be set on Linux
- Mic Equalizer -> Interesting to make the sound of the Mic Less Tinny (it is friendship-destroyingly tinny without any EQ tewaking!)
- Audio Equalizer

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

* `<len>` = 4 + the argument bytes that follow the `<arglen>`/`<seq>` byte.
* Request byte 6 (`<arglen>`) is **0x08 for every class-08 request ever
  captured**, and is *not* the payload length (those are 4-5 bytes long) —
  see §8.2.  A payload whose length differs from `<arglen>` is legal (Synapse
  does it constantly); an `<arglen>` larger than the frame is not.
* `<seq2>` is really the per-response sequence byte; `<ctr2>` turned out to be
  the first bytes of a 3-byte little-endian device timestamp (§8.2).
* Latency: settings reads answer in 13-38 ms.
* The dongle is strictly pull-based: 92 s of passive listening produced zero
  frames. It pushes only on state changes, e.g. replug produces a
  class-08 param 0x20 "flag 02, val 01" link event.

### Classes

* `0x08` — Synapse settings channel (works reliably, even on a fresh dongle):
  * read  : `03 <param> 00 <pad..>`
  * write : `04 <param> 00 <len> <val..>`
  * multi : `0d <param> 00 <n> <vals..>`
  * known params (from Synapse captures): ANC **mode** `0x12`/`0x92`
    (`0x00` off · `0x0a` on · `0xff` ambient — all confirmed by toggling; the
    1–10 *level* is software/transient and never persisted), EQ
    `0x1e`/`0x96`/`0x97`, sidetone `0x18` (0 off/1 on) + `0x19` (level, 0–15
    scale = `floor(% × 15/100)`: 10→1, 40→6, 50→7, 80→12, 100→15, writes
    `0x98`/`0x99`), power-saving
    `0x2c`/`0xac` (= timeout in minutes, `0x00` off · `0x0f`=15 · up to
    `0x3c`=60), link flag `0x20`.
  * **battery `0x21`** (read `03 21 00 00` → `0x5d` = 93, matching Synapse's UI
    2026-09-20), status byte `0x2a` = charge state (`0x00` on battery, `0x01`
    charging — verified by plug/unplug), version string `0x00` (reply ends
    `...IN`).  These came from the bare-metal capture, not the earlier (wedged)
    sweep.
  * **link `0x33`** (read) — **link signal strength / RSSI**, *not* a battery
    voltage (the old "×20 = mV" label was a coincidence).  Measured 2026-09-23:
    ~208–211 with the headset beside the dongle, falling monotonically to ~160
    at range edge before the link dropped, recovering back to ~208 on return.
    Unchanged by ANC toggles and by plugging in the charger, which rules out
    current/load.  Scale is 0–255-ish, higher = stronger; ~160 = marginal.
  * **Not on USB (software DSP in Synapse)** — THX↔Stereo spatial, Bass Boost,
    Mic Noise Cancellation, and Volume.  Confirmed by the fourth capture
    (2026-09-20): toggling each produced *zero* frames — no class-08 write, no
    audio-class control transfer.  Bass Boost was further confirmed by setting
    it to 60 % and reading no param change on Linux.  Synapse processes these
    in its own audio engine, so they never reach the dongle and are out of
    scope for USB RE (they are, correspondingly, the things you can set from
    Linux instead).
* `0x0e` → `0x01` — status poll: request `02 e1 01` (class 0x0e), reply
  `00 03 00 0e 88 ..` (class 0x01).  Synapse sent it ~20×/minute; the `88`
  marker echoes the battery blob's `09 88`.  Opt-in: `--probe-status`.
* class-08 `cmd 06` (`06 01 c2 03 f8 5f 04`) — periodic, byte-identical; looks
  like a time-sync/keepalive, not battery.
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
  Pro (053a) -> **only Synapse-shaped class-08 reads** (§8): the first frame is
  the link-flag read (param 0x20) that reliably answers on a healthy dongle
  (the ANC read 0x12 is flaky and was wrongly used as the liveness check). The
  battery is class-08 `param 0x21` (percent, verified live 2026-09-20) with a
  status byte on `0x2a`. `millivolts` is `None` on the Pro.
  `--sweep [LO-HI]` hunts for a class-08 battery parameter (anchor-gated,
  paced, aborts on silence) and `--legacy-console-probes` re-enables the old
  class-02/0x09 guesses, which have killed audio until a replug.
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
5. Class 0x08 is now pinned down against real Synapse traffic (§8); class 0x02
   (console) and class 0x09 still have no Synapse reference — a capture in
   which Synapse actually reads the battery would resolve both at once.  So
   far Synapse never touched them (§8.5).
6. **Which frame actually kills the dongle?** Candidate: our guessed class-02
   console frame (arglen 9) and the invented class-09 `cmd 04`.  Synapse only
   ever sends class 0x08 with arglen 8, and a dongle wedged by a hang answers a
   Synapse-identical class-08 read with silence (§9.2).  Test: a long
   class-08-only session (see the runbook,
   `docs/barracudapro-runbook.md` track C) must leave audio alive for hours.
7. Does the class-08 map contain a battery parameter at all?  Our old sweep
   that "found only 0x01/0x20" ran with mis-framed reads (arglen 3, 3-byte
   payload) and possibly mis-attributed replies — Synapse proves 0x12 and 0x2c
   answer, so that result is not trustworthy.  Re-run with
   `./barracuda_battery.py --sweep` (§9.3 step 2).

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

**Done 2026-09-20 — see §8.**  The capture nailed down the class-08 frame
grammar and the response envelope, but it contains **no battery query at all**
(no class-02/class-09 frame, no feature report, no `26 00 09 88` blob in
22 s); it needs to be repeated with the battery % visible in Synapse.

OpenRazer has no Barracuda (053a) support at all (its headset drivers cover
only the older Kraken family, which speak a different "control message"
protocol), so there is no reference implementation to copy. A USBPcap capture
of Synapse is therefore the recommended next step:

1. Install Wireshark on Windows **with the USBPcap component**.
2. Capture on the root hub hosting the dongle; open Synapse and let it poll
   for ~60 s while you (a) open the battery/headset panel, (b) unplug and
   replug the charger (charge-state change) and (c) power the headset off
   and on.
3. Keep only the dongle's traffic **by device address**, not by VID/PID:
   `usb.idVendor`/`usb.idProduct` exist only inside the device descriptor, so a
   display filter on them plus "export displayed packets" produces a 2-packet
   file with no traffic in it (happened 2026-09-20).  Use
   `usb.bus_id == 1 && usb.device_address == 2`, or export *all* packets and
   let `./pcapng_razer.py --extract out.pcapng --pid 053a --no-iso` do the
   selection.
4. What to look for: interrupt transfers on interface 3 (EP 3 OUT / EP 4 IN)
   carrying `01 80 <len> 50 41 …`; whether `<len>` always equals the payload
   length; which class carries the battery poll (0x02 console / 0x08 param /
   0x09 status) and its exact command bytes; the poll cadence; and whether
   Synapse sends anything after a query to flush the reply.

---

## 8. Synapse capture on Windows (USBPcap, 2026-09-20) — class-08 grammar confirmed

Source: `pcaps/Razer Synapse.pcapng` (5.0 MB, 7560 packets, **21.88 s**),
dumpcap/Wireshark 4.6.8 on 64-bit Windows 10 20H2 (build 19042) running in a
VM (the same root hub also carries a QEMU virtual HID device `0627:0001`),
captured on `\\.\USBPcap1`, link type 249.  Analyzer (stdlib only, no
Wireshark needed):

```
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng'                       # overview
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng' --devices             # descriptors
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng' --frames --vid 1532 --pid 053a
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng' --dump --dev 2        # hex+ascii
```

### 8.1 What is on the bus

| bus/dev | IDs | traffic (21.9 s) |
|---|---|---|
| 1/1 | `0627:0001` QEMU virtual HID | control + interrupt EP `0x81` — the VM's mouse/tablet, unrelated |
| 1/2 | **`1532:053a`** | enumeration control transfers, ISO EP `0x07` (audio OUT, 2188 URBs of 1920 B, never stops), **INT EP `0x03` OUT x10 + EP `0x84` IN x12** |

* The headset was linked and streaming audio for the whole capture, yet the
  only vendor traffic is **22 class-08 frames** (10 requests, 12 responses).
* No control transfer after `SET_CONFIGURATION` — no feature report, ever
  (confirms §1: this dongle declares none and Synapse never tries).
* No class-02 console frame, no class-09 frame and no `26 00 09 88` blob
  anywhere in the capture.
* The configuration descriptor (224 B, captured at t=0) confirms the layout:
  iface 0 = audio control, iface 1 alt 1 = EP `0x07` iso OUT 192 B, iface 2
  alt 1 = EP `0x88` iso IN 96 B, **iface 3 = HID (class 03/01, 103-byte report
  descriptor, EP `0x84` IN + EP `0x03` OUT, 64-byte interrupt, interval 1)**.
  So the PA/PI frames are HID **report id 1** reports on interface 3 = the
  "EP 3 OUT / EP 4 IN" of §1.

### 8.2 The frame envelope — confirmed and corrected

| off | request (`PA`) | response (`PI`) |
|-----|----------------|-----------------|
| 0 | `01` HID report id | `01` |
| 1 | `80` magic | `80` |
| 2 | `<len>` | `<len>` |
| 3-4 | `50 41` "PA" | `50 49` "PI" |
| 5 | `<class>` | `<class>` (the data's channel: 08 here) |
| 6 | `<arglen>` = **always `08`** for class 08 | `<seq>` per-response counter (`f4 f5 … ff`) |
| 7… | `03 <param> 00 00` · `04 <param> 00 <vlen> <val>` | `<tick(3)> 00 04 00 <param> <kind> 01 <value>` |

* `<len>` is exact and is counted **from byte 7**: read `01 80 08 …` = 4 + 4
  (`03 12 00 00`), write `01 80 09 …` = 4 + 5 (`04 92 00 01 ff`), response
  `01 80 0e …` = 4 + 10 (`f4 c6 28 be 00 04 00 12 01 01 0a`).  §2's rule
  "`<len>` = 4 + payload" is right, but "payload" must be counted *after* the
  `<arglen>`/`<seq>` byte, not after the class byte.
* **Correction:** request byte 6 is a constant `0x08`, *not* the payload
  length — Synapse sends it with 4-byte and 5-byte payloads alike.  It looks
  like a fixed 8-byte argument area.  `barracuda_battery.py::_frame()` still
  derives it from the payload length (which is what our class-02/09 probes
  want); it now takes `arglen=8` if a Synapse-shaped class-08 frame is needed.
* Response fields: class echo at [5], **per-response sequence byte** at [6]
  (`f4`…`ff`, +1 for every response, solicited or not), a **3-byte
  little-endian timestamp** at [7..9], then `00 04 00 <param> <kind> 01
  <value>` (param/kind/value at frame offsets 13/14/16).
  * The timestamp advances **exactly 800 ticks/s** (6080 ticks over the 7.600 s
    between responses #2 and #22) and matches the host's capture clock to
    <1 ms, i.e. it is the dongle's own clock; at capture time it read
    `0xbe28c6` = 12 462 278 ≈ 4.33 h.  §2's "`<seq2>` `<ctr2>`" pair was in
    fact the sequence byte plus the first timestamp bytes.
  * So the `01 c0` seen after `50 49` in the older z3ntu captures is class
    `01` + seq `c0`, not a fixed flag pair.
  * `<kind>` = `0x01` reply to our command, `0x02` **unsolicited event**
    (the dongle pushed these without any request, on the pending IN URB).
* Write acknowledgements carry `value = 0x00`, **not** the value that was just
  written — read the read-side parameter back to see the new state.

### 8.3 The whole transcript (all 22 frames)

| # | t (s) | dir | frame (hex, trimmed) | decoded |
|---|-------|-----|----------------------|---------|
| 1 | 6.1866 | req | `01 80 08  50 41 08 08 03 12 00 00` | read param `0x12` (ANC) |
| 2 | 6.1974 | rsp | `01 80 0e  50 49 08 f4  c6 28 be … 12 01 01 0a` | param `0x12` = `0x0a` (reply) |
| 3 | 6.2008 | req | `01 80 09  50 41 08 08 04 92 00 01 ff` | write `0x92` ← `0xff` |
| 4 | 6.2154 | rsp | seq `f5` | param `0x92` ack |
| 5 | 7.0076 | req | read `0x12` | |
| 6 | 7.0174 | rsp | seq `f6` | param `0x12` = `0xff` ← the value just written |
| 7 | 7.0202 | req | `04 92 00 01 0a` | write `0x92` ← `0x0a` |
| 8 | 7.0344 | rsp | seq `f7` | param `0x92` ack |
| 9 | 7.5254 | rsp | seq `f8` | param `0x12` = `0x0a`, **kind 02 — event, no request** |
| 10 | 7.5311 | req | read `0x12` | |
| 11 | 7.5424 | rsp | seq `f9` | param `0x12` = `0x0a` (reply) |
| 12 | 8.6974 | rsp | seq `fa` | param `0x12` = `0x0a`, **kind 02 — event** |
| 13 | 8.7014 | req | read `0x12` | |
| 14 | 8.7124 | rsp | seq `fb` | param `0x12` = `0x0a` (reply) |
| 15 | 13.1292 | req | `03 2c 00 00` | read `0x2c` (power saving) |
| 16 | 13.1404 | rsp | seq `fc` | param `0x2c` = `0x00` |
| 17 | 13.1416 | req | `04 ac 00 01 0f` | write `0xac` ← `0x0f` |
| 18 | 13.1624 | rsp | seq `fd` | param `0xac` ack |
| 19 | 13.7637 | req | read `0x2c` | |
| 20 | 13.7744 | rsp | seq `fe` | param `0x2c` = `0x0f` ← the value just written |
| 21 | 13.7760 | req | `04 ac 00 01 00` | write `0xac` ← `0x00` |
| 22 | 13.7974 | rsp | seq `ff` | param `0xac` ack |

Timing and plumbing:

* Request → response latency **10.7-21.4 ms** (matches §2's 13-38 ms).
* Every write is followed by a read of the read-side param, and both reads
  reflect the written value on the next poll → the `+0x80` read/write param
  pairing of §2 (`0x12`/`0x92`, `0x2c`/`0xac`) is confirmed end-to-end.
* No flush frame: all 10 requests use the **same** OUT URB and the responses
  arrive on two alternating IN URBs, i.e. Synapse simply keeps two reads
  pending at all times.  §3's "replies queue until the next write" is *not*
  what Synapse experiences — it is most likely an artifact of how our Linux
  probes read (and of the wedged/framed state after a malformed frame).
* The burst is a user fiddling with the UI (ANC on/off, power-saving on/off),
  not a periodic poll: 6.2 s and 13.1 s, with 4.5 s of silence in between.

### 8.4 What this confirms / refutes vs. the notes above

| note | capture says |
|---|---|
| §1 053a = interface 3, EP 3 OUT / EP 4 IN, 64-byte interrupt, report id 1, **no feature reports** | ✔ exactly (HID iface 3, 103-byte report desc, EP `0x03`/`0x84`, 64 B, interval 1). No control transfer after `SET_CONFIGURATION` — Synapse never touches feature reports |
| §2 envelope `01 80 <len> 50 41 <class> <arglen> …` | ✔ — but `<arglen>` is the constant `0x08` and `<len>` counts from byte 7 |
| §2 response `… 50 49 01 c0 <seq2> <ctr2> …` | ✔ shape; `01` = class, `c0` = seq; `<ctr2>` is a 3-byte 800 Hz timestamp |
| §2 class 08 read `03 <param> 00`, write `04 <param> 00 <len> <val>` | ✔ commands; ✔ params `0x12`/`0x92` and `0x2c`/`0xac`; the captured read payload is 4 bytes: `03 <param> 00 00` |
| §2 read latency 13-38 ms | ✔ 10.7-21.4 ms measured |
| §2 "strictly pull-based … pushes only on state changes" | ✔ — 2 spontaneous `kind 02` frames with no request in flight |
| §2 "no battery parameter exists on class 0x08" | ✔ — none of the 22 frames touched one |
| §2 params: a 256-param sweep found only `0x01`/`0x20` | ✔ consistent — Synapse only used `0x12` and `0x2c` |
| §3 "replies queue and are only flushed by the next write" | ✘ — Synapse gets replies 10.7-21.4 ms after each request with no flush frame (two IN URBs kept pending) |
| §7 "an `arglen` mismatch wedges the dongle" | refined — `arglen 0x08` with a 4-byte payload is *normal* Synapse traffic, so a mismatch alone is not the trigger; `arglen 0x40` (bigger than the frame) is the better suspect |

### 8.5 The big negative: no battery query, and what to capture next

* **Synapse did not ask for the battery once in 22 s.**  No class-02 console
  frame, no class-09 frame, no feature report, no `26 00 09 88` blob.  The
  entire vendor session is ANC (`0x12`/`0x92`) and power-saving
  (`0x2c`/`0xac`) settings.
* The dongle was (re-)enumerated at t=0 and Synapse opened it at 6.19 s — its
  **first** frame is an ANC read, not a battery read.  So a fresh open does not
  poll the battery either; either the battery UI was not open, or this device
  has no battery readout in Synapse, or it is polled on a much slower timer
  than 22 s.
* Repeat the capture, longer and with the battery visible:
  1. open the Synapse page that shows the headset battery (if it has one) and
     keep it on screen;
  2. capture 5-10 min instead of 22 s (the whole capture is only 5 MB, mostly
     audio, so length is cheap);
  3. while capturing: plug/unplug the charger, power the headset off/on, press
     the ANC button — that is also how the charge-state codes (`0x07` = ?) and
     the console append-mode trigger (§3, §6) get settled;
  4. analyse with `./pcapng_razer.py CAP --dump --vid 1532 --pid 053a` and look
     for anything that is not class 08.
* If Synapse turns out to have no battery readout for the 053a at all, then the
  class-09 `cmd 04` blob and the console `bat` line (§4) remain the only known
  source, and the append-mode trigger is still the thing to solve.

---

## 9. Where to go from here (safe probing order)

The same steps as a copy-paste runbook, with decision tables and a log
template: **`docs/barracudapro-runbook.md`**.

### 9.1 The tools are Synapse-shaped by default now

| command | frames sent | status |
|---|---|---|
| `./barracuda_battery.py` (Pro dongle) | class-08 reads: link `0x20` + status `0x2a` + battery `0x21` (plus a class-0x0e unlock poll) | battery verified live |
| `./barracuda_battery.py --features` | warm-up + read every known param | verified |
| `./barracuda_battery.py --watch [S]` | unlock + paced `0x2a`/`0x21`/`0x33` reads | verified |
| `./barracuda_battery.py --set-anc / --set-sidetone / --set-power-save / --set` | class-08 writes (`read param + 0x80`), verified by read-back | verified safe (writes don't kill audio) |
| `./barracuda_battery.py --sweep [LO-HI] [--pace S] [--dry-run]` | class-08 reads, paced, anchor-gated, aborts after 3 silences | safe shape |
| `./barracuda_battery.py --legacy-console-probes` | class-02 console `bat` + class-09 `cmd 04` | **prime suspect for the hangs** |

**Safety note (2026-09-20):** a live *warm-up + full 128-param sweep* (the
Synapse open sequence — `write d6=2`, `write d6=1`, read link `0x20`, class-0x0e
poll, read status `0x2a`, read battery `0x21` — followed by a paced read of every
param `0x00`–`0x7f`) ran without killing audio.  So the "safe surface" is wider
than reads alone: the class-08 **writes** (`d6`) and the class-`0x0e`/`0x01`
**status poll** are also safe on Linux, and a full class-08 sweep is fine.  The
hang trigger remains specific to class-02/0x09, not to "any probing".

Two other fixes in the same pass:

* replies are now attributed by their *own* param field, so an answer that
  arrives one frame late cannot be credited to the wrong parameter — the old
  256-param sweep (§2) may simply have mis-read the map that way;
* a read is retried once before it counts as silence, so §3's "the reply only
  flushes when the next frame is written" cannot masquerade as an empty param.

### 9.2 Is the dongle wedged right now? (one-frame test)

```bash
./barracuda_battery.py --sweep 20 --dry-run   # print the frame, send nothing
./barracuda_battery.py --sweep 20             # link-flag read (param 0x20)
```

* `# link 0x20 -> 00 04 00 20 01 01 01` (value 1 = linked) → the channel is
  healthy;
* pure silence → possibly wedged (§7).  **Correction (2026-09-20):** the
  original anchor was the ANC read `0x12`, but that param is flaky — it can be
  silent on a perfectly healthy dongle with audio still playing.  Silence to
  `0x12` does NOT imply a wedge; `0x20` (link flag) is the reliable liveness
  signal, and `0x21` (battery) is what we actually want.  A genuine wedge
  (audio dead, still enumerated) is silent to everything, including `0x20`.

### 9.3 Next steps, in order

1. Replug the dongle and run `./barracuda_battery.py --sweep 12`. This settles
   §7's open question: if the anchor answers on a fresh dongle, our class-08
   framing is right and the class-02/class-09 frames are the crash trigger.
2. If the anchor answers, run `./barracuda_battery.py --sweep` (all of 0x00-0x7f,
   ~40 s) and look for a small value (percent) or a multi-byte payload. Put the
   param in `PRO_BATTERY_PARAMS` and the reader works on the Pro.
3. If even a fresh dongle ignores the anchor, our hidraw path differs from
   Synapse's in a way Linux cannot show us — then only §9.4 helps.
4. Capture Synapse in Windows with the battery on screen (§9.4).

### 9.4 Windows capture recipe (the authoritative route)

1. In Synapse, open the Barracuda Pro page and **check whether it shows a
   battery percentage at all**; note the value and whether it ever changes.
2. Start dumpcap/USBPcap on the hub hosting the dongle **before** plugging the
   dongle in, so the enumeration and Synapse's first frames are inside the
   capture; then capture **5-10 min** (the whole 22 s capture was 5 MB, mostly
   audio — length is cheap).
3. Leave it alone for the first minute (that reveals the poll cadence), then:
   plug/unplug the charger, power the headset off and on, press the ANC button,
   and move every control in the page (ANC modes, EQ, mic monitor, power
   saving) one at a time, 2-3 s apart.
4. Stop the capture, export it (see
   §10.1: filter on `usb.bus_id`/`usb.device_address`, **never** on
   `usb.idVendor`/`usb.idProduct` - those fields live only in the device
   descriptor), and decode it in seconds without Wireshark:

   ```bash
   ./pcapng_razer.py CAP --frames --vid 1532 --pid 053a
   ./pcapng_razer.py CAP --extract small.pcapng --pid 053a --no-iso   # shrink
   ./pcapng_razer.py small.pcapng --dump --vid 1532 --pid 053a | grep -v ' iso '
   ```

5. What would settle it: **any** frame that is not `class 08 cmd 03/04` (that is
   the battery path we cannot guess), or a class-08 read of an unseen param
   (anything besides `0x12`/`0x2c`; a battery percent is a natural candidate for
   a once-a-minute poll).  If Synapse reads no battery for this device at all,
   then the battery really lives only on the class-02/0x09 path of §4, and §3/§7
   have to be re-opened with `arglen <= 8` framing.

---

## 10. Capture inventory & the empty-export trap

| file (in `pcaps/`, git-ignored) | md5 | captured | span | size | what is in it |
|---|---|---|---|---|---|
| `Razer Synapse.pcapng` | `81cddc48…` | 2026-09-20 | 21.876 s | 5.0 MB | 7560 packets: dongle enumeration + full config descriptor, 2188 audio URBs, **all 22 class-08 PA/PI frames** (§8.3), and an unrelated QEMU HID device on the same hub |
| `Razer Synapse new.pcapng` | `b773bec2…` | 2026-09-20 | 153.754 s | 448 B | **2 packets only** — two 18-byte device descriptors (t=0 and t=153.75), nothing else |
| `third - bare metal windows.pcapng` | `b6ece373…` | 2026-09-20 | 163.348 s | 118.6 kB | 1446 packets, one root hub: dongle enumerated 3× (dev2/10/11), **272 PA/PI frames** — battery `0x21` = 93 (Synapse UI matched), status `0x2a`, version `0x00`, class-0x0e/0x01 poll, `cmd 06`; no isochronous audio |
| `fourth - bare metal windows.pcapng` | `0e02344f…` | 2026-09-20 | 86.768 s | 33.6 kB | 446 packets: dongle = enumeration + one `SET_INTERFACE` + 6 ANC (`0x12`) polls.  **Proof that THX↔Stereo / Bass / Mic-NC / Volume are software DSP** — toggling them produced no frames at all |

### 10.1 What went wrong in the 448-byte capture

It was exported from Wireshark with *Export Specified Packets → Displayed* while
the display filter `usb.idVendor == 0x1532 && usb.idProduct == 0x053a` was
active.  Those two fields exist **only inside the device descriptor**, so no
other packet can ever match: the file ends up holding the descriptor data
stages and nothing else.  Two details confirm that diagnosis:

* even the 8-byte *setup* stages are missing (they carry no VID/PID either),
  which rules out a USBPcap capture filter — that one selects whole devices and
  would have kept all of the dongle's traffic;
* `pcapng_razer.py` sees no interrupt/iso/bulk transfer in the file at all.

The two descriptors 153.75 s apart do show that the dongle enumerated twice in
that window, i.e. it was replugged or reset by Windows — but with no data
packets recorded the capture says nothing about the protocol.

### 10.2 Correct way to trim a capture

```bash
# in Wireshark: filter by address, not by IDs, and then export displayed packets
#   usb.bus_id == 1 && usb.device_address == 2
# or simply export everything and let our tool do the selecting:
./pcapng_razer.py 'pcaps/Razer Synapse.pcapng' --extract small.pcapng --pid 053a --no-iso
#   4426 of 7560 packets kept, 5.0 MB -> 4.9 kB (the isochronous audio is >99 %
#   of the bytes; all 22 PA/PI frames and the descriptors survive)
```

With `--no-iso` the kept span shrinks to the first..last kept packet (the audio
that filled the gaps is gone), so read the frame timestamps, not the header
span, when comparing runs.

`pcapng_razer.py` now prints a hint when a capture contains no
interrupt/iso/bulk transfer at all, and `--devices` says explicitly when a
known device has no configuration descriptor in the file — both are exactly
this failure mode.

