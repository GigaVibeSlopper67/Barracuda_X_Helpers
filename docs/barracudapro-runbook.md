# Barracuda Pro (053a) — reverse-engineering runbook

Step-by-step instructions for the next round of work on the **Razer Barracuda
Pro 2.4** dongle (`1532:053a`).  Goal: find the command that returns the
headset's **battery** (percent + charge state) — or prove that no such command
exists over USB — without killing the dongle again.

Read first (same directory):

* `barracudapro.md` §7 — the hang incident (audio died until a USB replug);
* §8 — the frame grammar **verified against Synapse's own traffic**;
* §9 — what the tools send today and how to tell a wedged dongle;
* §10 — capture inventory + the empty-export trap.

Convention: `§n` references in this file point into `barracudapro.md`; this
runbook's own sections are referred to as “section n”.

Findings go back into `barracudapro.md` (§2 classes/params, §4 blob layout,
§8.3 transcript tables, §10 inventory) and into the README's Pro section.

---

## 0. Ground rules (do not break these)

1. **Only Synapse-shaped frames.**  class `0x08`, `03 <param> 00 00` (read) or
   `04 <param> 00 <vlen> <val>` (write), `arglen` byte = `0x08`, `<len>` byte =
   4 + argument bytes, 64-byte HID report id 1.  These are the only frames ever
   seen on the wire, and they are byte-identical for the parameters Synapse
   reads (§8.2/§8.3).
2. **One frame at a time, paced.**  ≥ 0.25 s between reads, never a burst.  The
   tools already pace (`--sweep`, `--pace`).
3. **Anchor first.**  Every session starts by reading param `0x12` (ANC) — the
   very frame Synapse sends when it opens the device.  No answer ⇒ the dongle is
   wedged: **stop, replug, restart** (§9.2).  Never keep probing a silent dongle.
4. **Do not send class `0x02` / `0x09`** except in track C.  Synapse never uses
   them, they are the prime suspect for the hangs, and the console is
   state-dependent.  If they are ever sent: `arglen` must equal the payload
   length and must stay ≤ 8, one frame every few seconds, replug at hand.
5. **A wedged dongle is not a dead dongle.**  It stays enumerated (ALSA card
   present) and answers nothing; a replug has always restored it so far.
6. Do not leave `barracuda-watch` / `barracuda-tray` polling a `053a` dongle
   (5 s / 30 s ticks, each one sends reads).
7. **Record everything** (see section 6): sweep output, capture files + md5s,
   what the Synapse UI was showing, and the dongle's state.

---

## 1. Where we are (one screen)

| known | where |
|---|---|
| device — iface 3 is HID 03/01, report id 1, EP 3 OUT / EP 4 IN, 64 B, no feature reports | §1, §8.1 |
| envelope — `01 80 <len> 50 41\|49 <class> <arglen\|seq> <payload…>`, `<len>` = 4 + argument bytes after byte 6 | §8.2 |
| class 0x08 — read `03 <param> 00 00`, write `04 <param> 00 <vlen> <val>`, `arglen` always `0x08` | §8.2/§8.3 |
| reply — class echo, per-response `seq`, 3-byte LE timestamp at 800 ticks/s, `00 04 00 <param> <kind> 01 <val>`; kind `01` = reply, `02` = unsolicited event | §8.2 |
| params Synapse uses — `0x12` ANC (`0x0a`/`0xff` seen), `0x2c` power saving (`0x00`/`0x0f`); write side = read + `0x80` | §8.3 |
| write acks answer `value = 00`, so verify a write by reading the parameter back | §8.2 |
| the battery blob (`26 00 09 88`) has only ever come from class `0x02`/`0x09` — the risky path | §4 |
| **missing: how the battery is read (percent + charge state)** | §6 |

---

## 2. Track A — Linux sweep (5 minutes, start here)

### A1 — health check

```bash
./barracuda_battery.py --sweep 12 --dry-run   # prints the frame, sends nothing
./barracuda_battery.py --sweep 12             # anchor read + param 0x12
```

Healthy dongle (this is what "our framing is right" looks like):

```
# anchor 0x12 -> 00 04 00 12 01 01 0a
# 1 of the 1 params asked answered
  0x12 value=10 (0x0a) data=00 04 00 12 01 01 0a
```

* `value=10` is the ANC mode that Synapse reported for the same parameter
  (§8.3) — seeing it means the class-08 channel speaks to us.
* Silence ⇒ replug and repeat.  **Two** clean runs that stay silent on a freshly
  plugged dongle is itself a result: record it and jump to track B (it would
  mean the Linux path differs from Synapse's, not that the frame is wrong).

### A2 — full parameter sweep

```bash
./barracuda_battery.py --sweep | tee /tmp/sweep-$(date +%F-%H%M).txt
```

All of `0x00`–`0x7f`, paced at 0.25 s (≈40 s).  It aborts after three consecutive
silent parameters and always prints the anchor result first.

### A3 — sanity anchors

`0x12` and `0x2c` **must** answer (Synapse reads both).  If they do not, the run
is invalid: check the anchor, replug, retry once, then stop and record.

### A4 — flip test on anything battery-shaped

```bash
./barracuda_battery.py --sweep 12-2f     # the range that held the candidate(s)
```

Read the candidates while the state changes:

| condition | how |
|---|---|
| charger | read with the charger in, unplug it, wait 20 s, read again |
| headset link | read, power the headset off, wait 30 s, read again |
| charge level | read once a minute while the level drops (or while charging) |

The battery is percent-plus-state, so a real candidate either carries a small
value (≤ 100) that moves with the charger/link, or a **multi-byte** payload
(anything longer than the usual `00 04 00 <param> 01 01 <val>`).

### A5 — wire it into the code

```python
# barracuda_battery.py
PRO_BATTERY_PARAMS = (0x??,)      # read-side param(s) that answered
```

then `./barracuda_battery.py` and `./barracuda_battery.py --json` must print
`Battery: NN% (class-08 param 0x??)` — and `-v` shows the raw reply.

---

## 3. Reading a sweep result

| observation | meaning | next |
|---|---|---|
| `0x12 value=10 (0x0a)` | channel healthy, framing correct | continue |
| `0x12`/`0x2c` answer, most params silent | normal — unknown params answer silence | look at the answered set (the final table lists them all) |
| only the anchor answers, then three silences | dongle wedged mid-sweep | replug, retry once, record |
| a param with `kind=02` | the dongle *pushed* a state-change event | record param + value (compare with §8.3's two events) |
| `value` ≤ 100 that moves with the charger | battery percent candidate | flip test (A4), then A5 |
| payload longer than the 7 usual data bytes | structured blob (state + mV + %?) | compare across conditions, derive the layout, document it in §4 |
| answers for `0x00`–`0x01`/`0x20` only | suspicious — that is the *old* mis-framed result (§6 item 7, §8.4 last rows) | re-check the anchor and repeat |
| everything answers but nothing changes | params are configuration, not telemetry | track B |

Write the whole table down (the `--sweep` output is the record), including the
silent ones: a *negative* sweep is a result too.

---

## 4. Track B — Windows capture (authoritative, ~20 min)

Do this whenever track A finds nothing, or to cross-check a candidate.

1. **Before capturing**: open Synapse's Barracuda Pro page and note whether it
   shows a **battery percentage at all**, its value, and whether the value ever
   moves.  If Synapse has no battery readout for this device, do not expect a
   battery command to exist — that is a decisive (negative) result.
2. Start dumpcap/USBPcap on the root hub hosting the dongle **before** plugging
   the dongle in, so enumeration + Synapse's first frames are inside the
   capture.  Capture 5–10 min (the 22 s reference capture was 5 MB, mostly
   audio).
3. Script of actions (write the wall-clock times down as you go):
   * 0–60 s: touch nothing (reveals the poll cadence);
   * plug the charger, wait 60 s, unplug, wait 60 s;
   * power the headset off, wait 30 s, on, wait 30 s;
   * press the ANC button (known param `0x12`, so it validates the capture);
   * move every control in the page one at a time, 3 s apart: ANC modes, EQ,
     mic monitor, power saving, …;
   * stop the capture.
4. Stop and export — **no display filter**.  (Filtering on
   `usb.idVendor`/`usb.idProduct` in Wireshark produced a 2-packet file with no
   traffic at all; see §10.1.)  If you must trim inside Wireshark, filter on
   `usb.bus_id`/`usb.device_address`, then *Export Specified Packets →
   Displayed*.
5. Shrink and decode locally:

   ```bash
   ./pcapng_razer.py CAP --extract small.pcapng --pid 053a --no-iso   # ~5 kB
   ./pcapng_razer.py small.pcapng --frames --vid 1532 --pid 053a
   ./pcapng_razer.py small.pcapng --dump --vid 1532 --pid 053a | grep -v ' iso '
   ```

   `--frames` prints one decoded block per PA/PI frame, so anything unexpected
   is visible immediately (it decoded the 22 reference frames as
   `class=08 cmd=03(read) param=12` and `param=12 kind=01(reply) value=10`).
6. What counts as the breakthrough:
   * **any frame that is not `class 08 cmd 03/04`** — that is the battery path
     we cannot guess (a class-0x09 status frame would be the §4 blob);
   * a **class-08 read of an unseen parameter** (anything besides `0x12`/`0x2c`),
     especially one repeated on a timer;
   * a class-08 read that appears right before Synapse's battery number updates.
7. Then: decode that parameter on Linux with `./barracuda_battery.py --sweep
   <param>`, run the flip test (A4) and wire it in (A5).


---

## 5. Track C — only if Synapse reads no battery (or to prove what kills the dongle)

Nothing here is needed to *find* the battery; it exists because §4 shows the
blob `26 00 09 88` can come out of class `0x02`/`0x09`, and because we still do
not know which frame wedges the dongle.

### C1 — long class-08-only session (tests the crash trigger)

```bash
# ~2 frames a minute for 30-60 minutes, with audio playing so you can hear it die
for i in $(seq 30); do ./barracuda_battery.py --sweep 12; sleep 60; done
```

* audio survives the whole run ⇒ class-08 traffic is safe, and the
  class-02/0x09 frames (or the old mis-framed reads) are confirmed as the
  trigger — record it and keep the console out of the default path forever;
* audio dies mid-run ⇒ class-08 traffic can wedge it too (or the firmware has an
  unrelated bug).  Record the run length and the last frame sent.

### C2 — console frames that respect the 8-byte argument area

Only with a replug at hand.  Invariant: `arglen` = payload length, ≤ 8, one
frame every few seconds.  The old `bat` frame used a 9-byte payload
(`arglen 09`); the 8-byte variants line the text up differently, because the
console's line editor consumes the frame text itself (“PA” + class + arglen):

| payload (class `0x02`) | intended console line |
|---|---|
| `08 08 08 08 62 61 74 0d` | 4 backspaces + `bat` + CR |
| `08 08 08 08 62 61 74 20` | 4 backspaces + `bat ` + space |

There is deliberately no CLI for these; build the frame with the documented
helper so the lengths can never disagree:

```python
import os
from barracuda_battery import _frame

fd = os.open("/dev/hidrawN", os.O_RDWR | os.O_NONBLOCK)
os.write(fd, bytes(_frame(0x02, b"\x08\x08\x08\x08bat\r")))   # arglen = 8, len = 12
```

Then read the IN endpoint for a few seconds and look for either a console line
`"bat is not a valid command"` (data mode: the text never reached the line) or
the status frame `01 00 26 00 09 88 <36 bytes>` (the §4 blob).  Anything else is
new information — write the raw bytes down.

Success criterion: the blob appears **reproducibly** (three runs in a row after
a fresh replug).  Only then is it worth building a reader around it.

---

## 6. Where to write results

| result | file | what to add |
|---|---|---|
| new class-08 parameter or value | `docs/barracudapro.md` §2 classes + README “Known params” | param, direction (write = read + `0x80`), observed values |
| the battery parameter | `barracuda_battery.py` → `PRO_BATTERY_PARAMS`, plus README and §4 | percent field, state field, flip-test evidence |
| new frames (any class) | `docs/barracudapro.md` §8.3-style table, one row per frame | t, direction, raw hex, decode |
| a capture worth keeping | §10 inventory table | filename, md5, date, span, size, contents |
| a wedged/killed dongle | §7 incident log | what was sent, how many frames, did a replug restore it |

Log template:

```
Capture      : pcaps/<name>  md5 <…>   <date>   <span> s   <size>
Tool         : dumpcap/USBPcap <version> on <Windows build>, USBPcap<n>
Synapse      : <version>, page open: <…>, battery shown: <yes/no, value>
Dongle state : fresh replug? uptime? wedged before?
Actions      : <timeline: charger in/out, headset off/on, ANC, UI clicks>
Frames       : ./pcapng_razer.py <cap> --frames --vid 1532 --pid 053a   → <paste>
Sweep        : ./barracuda_battery.py --sweep                          → <paste>
Conclusion   : <param 0x?? = battery percent, or: no battery command exists>
```

---

## 7. Handover checklist (what to send back)

1. The `--sweep` output **including the anchor line**.
2. The capture: the raw pcapng, or the shareable `--extract … --no-iso` file
   (≈5 kB even for a 10-minute capture) plus its md5.
3. What the Synapse UI showed (battery present? value? did it change?).
4. Any unexpected frame bytes, and whether audio survived the session.

