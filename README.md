# UDS Fuzzer Lab: breaking a simulated ECU 3 ways

**Sprint 1, AV SEC lab 1.** This project is a mutation-based fuzzer for UDS (ISO 14229) car diagnostics. It runs against a simulated ECU that has 3 bugs planted in it on purpose. Everything runs on a software CAN bus. **No real vehicle was touched.**

## Results (seed 1337, 5,000 cases, 18.9 s)

| # | Type | Trigger | Found at case | What happened |
|---|------|---------|---------------|---------------|
| 1 | **CRASH** | `22 F1` (ReadDataByIdentifier, DID cut short) | 123 | ECU firmware read a byte that wasn't there and died. It never answered again until power-cycled. |
| 2 | **BYPASS** | `10 03` then `27 02 00 00` (SecurityAccess sendKey, all-zero key) | 162 | ECU unlocked with no seed requested. Proof: the protected DID `F1F0` returned `53 45 43 52` ("SECR"). |
| 3 | **HANG** | `31 01 FF 00` (RoutineControl start, routine 0xFF00) | 2,549 | ECU went silent for ~3 s, then recovered. A forgotten debug routine blocked the main loop. |

Traffic seen: 4,764 cases sent · 643 positive · 4,088 negative (NRC) · 33 silent · 236 skipped (known-bad buckets).

## How it works

1. **Corpus.** It starts from 7 valid requests a scan tool would send (`10 03`, `22 F1 90`, `27 01`, ...).
2. **Mutate.** It swaps in edge bytes (`00 7F 80 FF`), flips bits, truncates, appends junk, and drops in "interesting" 16-bit IDs from a dictionary (`0000`, `FFFF`, `FF00`, ...).
3. **Clean state each time.** It sends `11 01` (reset) before every case, and half the time it also enters the extended session (`10 03`).
4. **Three oracles** (bug detectors):
   - **Crash:** no reply, and no reply to TesterPresent (`3E 00`) for 4.5 s.
   - **Hang:** no reply at first, but the ECU recovers inside that window.
   - **Bypass:** a positive `67 02` (unlocked) even though the fuzzer never computes a key. It then confirms by reading a protected DID.
5. **Triage.** Findings are de-duplicated by type and service. After a crash or hang, the fuzzer skips that (service, length) bucket so it doesn't keep re-killing the ECU, then "power-cycles" the ECU and continues.

Random bytes alone almost never hit bugs 2 and 3, because each needs 3–4 exact bytes. **Corpus + dictionary mutation** is what made them findable in seconds. That's the same idea behind AFL dictionaries.

## Run it

```bash
pip install python-can
python fuzzer.py --cases 5000 --seed 1337          # fuzz, writes findings.json
python fuzzer.py --replay "27 02 00 00" --setup "10 03"   # reproduce a finding
```

Moving to real SocketCAN (Linux / Kali VM) is a one-line change in both files:
```python
can.Bus(interface="socketcan", channel="vcan0")
```

## Fixes, mapped to ISO/SAE 21434 thinking

| Bug | Root cause | Fix | 21434 angle |
|-----|-----------|-----|-------------|
| Crash | Length check `>= 2` should be `>= 3`. The parser trusts its input. | Validate the length before indexing, and return NRC `0x13`. Add a watchdog so a fault resets the ECU safely. | Weakness found in verification testing (Clause 10). Fuzzing should be part of the test plan. |
| Bypass | Factory backdoor key left in production firmware | Remove the debug keys. Use a strong seed/key (or certificate-based auth). Add attempt counting and a delay (NRC `0x36`/`0x37`). | Highest risk of the three. Lets an attacker unlock the ECU and read protected data. A TARA (threat analysis) would flag it as a high-impact threat that has to be fixed. |
| Hang | Debug routine reachable in the default session, runs synchronously | Remove it, or require an unlocked programming session. Make long routines async and answer NRC `0x78` (responsePending). | Availability. A diagnostic denial-of-service on the vehicle network. |

## Limits (being honest)

- Single-frame ISO-TP only (≤7 bytes). Multi-frame messages are a next step.
- The oracles watch the bus only. A real target would also need power, current and debug-port monitoring.
- The bugs were planted, so this shows the *method*, not a real-world discovery.

## Next

- [ ] Run on Kali + `vcan0` + ICSim
- [ ] Add multi-frame ISO-TP (`python-can-isotp`)
- [ ] Coverage-guided mode: favor mutations that produce new response codes
