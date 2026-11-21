"""
UDS fuzzer for the fake ECU in ecu_sim.py.

How it works (the short version):
  1. Start from a small CORPUS of valid UDS requests (things a scan tool sends).
  2. MUTATE them: swap in edge-case bytes, flip bits, cut them short, add junk,
     or drop in "interesting" 16-bit IDs from a DICTIONARY.
  3. Send each mutated request and watch with three ORACLES (bug detectors):
       - CRASH:  the ECU stops answering and never comes back
       - HANG:   the ECU stops answering for a while, then recovers
       - BYPASS: the ECU says "unlocked" even though we never computed a key
  4. Save each unique finding with the exact bytes needed to reproduce it.

Usage:
  python fuzzer.py --cases 5000 --seed 1337
  python fuzzer.py --replay "27 02 00 00" --setup "10 03"

Simulation only. Fuzzing a real vehicle can brick ECUs or worse.
"""
import argparse
import json
import random
import time

import can

from ecu_sim import FakeECU, REQ_ID, RESP_ID

CHANNEL = "uds_lab"
REPLY_TIMEOUT = 0.3     # seconds to wait for a normal answer
RECOVERY_WINDOW = 4.5   # seconds to wait before calling it a crash (vs a hang)

# Valid requests a real diagnostic tool might send. Mutations start from these.
CORPUS = [
    bytes([0x10, 0x03]),              # enter extended session
    bytes([0x11, 0x01]),              # hard reset
    bytes([0x22, 0xF1, 0x90]),        # read VIN
    bytes([0x27, 0x01]),              # request security seed
    bytes([0x27, 0x02, 0x12, 0x34]),  # send security key (a wrong one)
    bytes([0x31, 0x01, 0x02, 0x03]),  # start routine 0x0203
    bytes([0x3E, 0x00]),              # tester present ("are you there?")
]

EDGE_BYTES = [0x00, 0x01, 0x02, 0x03, 0x7F, 0x80, 0xFE, 0xFF]
# 16-bit values that often hide bugs: zeros, all-ones, boundaries, debug-ish IDs.
DICT16 = [0x0000, 0xFFFF, 0xFF00, 0x00FF, 0x8000, 0x7FFF,
          0xF190, 0xF1F0, 0xF000, 0x0203]


def hexs(b):
    return " ".join(f"{x:02X}" for x in b)


def parse_hex(s):
    return bytes(int(x, 16) for x in s.split()) if s else b""


# ---------------- mutation engine ----------------
def mutate(rng, base):
    p = bytearray(base)
    for _ in range(rng.choice([1, 1, 2])):
        op = rng.choice(["edge", "bitflip", "dict16", "truncate", "append"])
        if op == "edge" and len(p) > 1:
            p[rng.randrange(1, len(p))] = rng.choice(EDGE_BYTES)
        elif op == "bitflip" and len(p) > 1:
            i = rng.randrange(1, len(p))
            p[i] ^= 1 << rng.randrange(8)
        elif op == "dict16" and len(p) >= 3:
            i = rng.randrange(1, len(p) - 1)
            v = rng.choice(DICT16)
            p[i], p[i + 1] = v >> 8, v & 0xFF
        elif op == "truncate" and len(p) > 1:
            p = p[:rng.randrange(1, len(p))]
        elif op == "append" and len(p) < 7:
            p.append(rng.randrange(256))
    return bytes(p)


def random_case(rng):
    return bytes(rng.randrange(256) for _ in range(rng.randint(1, 7)))


def generate(rng):
    if rng.random() < 0.8:
        req = mutate(rng, rng.choice(CORPUS))
    else:
        req = random_case(rng)
    setup = [bytes([0x10, 0x03])] if rng.random() < 0.5 else []
    return setup, req


# ---------------- talking to the ECU ----------------
class Tester:
    def __init__(self):
        self.bus = can.Bus(interface="virtual", channel=CHANNEL, receive_own_messages=False)

    def drain(self):
        while self.bus.recv(timeout=0) is not None:
            pass

    def send(self, payload):
        frame = (bytes([len(payload)]) + payload).ljust(8, b"\x00")
        self.bus.send(can.Message(arbitration_id=REQ_ID, data=frame, is_extended_id=False))

    def request(self, payload, timeout=REPLY_TIMEOUT):
        self.send(payload)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            msg = self.bus.recv(timeout=max(0, end - time.monotonic()))
            if msg and msg.arbitration_id == RESP_ID:
                d = bytes(msg.data)
                return d[1:1 + (d[0] & 0x0F)]
        return None

    def healthy(self):
        return self.request(bytes([0x3E, 0x00])) == bytes([0x7E, 0x00])

    def wait_for_recovery(self):
        start = time.monotonic()
        while time.monotonic() - start < RECOVERY_WINDOW:
            if self.healthy():
                return time.monotonic() - start
        return None


# ---------------- the fuzz loop ----------------
def run_case(tester, setup, req):
    """Returns (finding_type or None, response, detail)."""
    tester.drain()
    tester.request(bytes([0x11, 0x01]))          # reset to a clean state first
    for s in setup:
        tester.request(s)
    resp = tester.request(req)

    # Oracle 3: BYPASS. We never computed a real key, so "unlocked" is a bug.
    if resp is not None and resp[:2] == bytes([0x67, 0x02]):
        proof = tester.request(bytes([0x22, 0xF1, 0xF0]))  # read protected DID
        return "BYPASS", resp, f"protected DID read returned: {hexs(proof) if proof else 'nothing'}"

    if resp is None and not tester.healthy():
        recovered_after = tester.wait_for_recovery()
        if recovered_after is None:
            return "CRASH", None, f"no answer for {RECOVERY_WINDOW}s"
        return "HANG", None, f"unresponsive, recovered after ~{recovered_after + 2 * REPLY_TIMEOUT:.1f}s"
    return None, resp, ""


def fuzz(cases, seed, out_path):
    rng = random.Random(seed)
    ecu = FakeECU(channel=CHANNEL)
    ecu.start()
    tester = Tester()

    findings = {}            # signature -> finding
    known_bad_buckets = set()
    stats = {"sent": 0, "skipped_known": 0, "positive": 0, "negative": 0, "silent": 0}
    t0 = time.monotonic()

    for i in range(cases):
        setup, req = generate(rng)
        bucket = (req[0], len(req))
        if bucket in known_bad_buckets:
            stats["skipped_known"] += 1   # don't keep re-triggering a known crash/hang
            continue
        stats["sent"] += 1
        kind, resp, detail = run_case(tester, setup, req)

        if resp is None:
            stats["silent"] += 1
        elif resp[0] == 0x7F:
            stats["negative"] += 1
        else:
            stats["positive"] += 1

        if kind:
            sig = f"{kind}:SID_0x{req[0]:02X}"
            if sig not in findings:
                findings[sig] = {
                    "type": kind,
                    "service": f"0x{req[0]:02X}",
                    "setup": [hexs(s) for s in setup],
                    "request": hexs(req),
                    "response": hexs(resp) if resp else None,
                    "detail": detail,
                    "first_case": i,
                    "hits": 0,
                }
                print(f"[case {i:5d}] NEW {kind:6s}  setup={[hexs(s) for s in setup]}  "
                      f"req=[{hexs(req)}]  {detail}")
            findings[sig]["hits"] += 1
            if kind in ("CRASH", "HANG"):
                known_bad_buckets.add(bucket)
            if kind == "CRASH":              # "power-cycle" the dead ECU
                ecu.stop()
                ecu = FakeECU(channel=CHANNEL)
                ecu.start()

    ecu.stop()
    tester.bus.shutdown()
    elapsed = time.monotonic() - t0

    report = {"seed": seed, "cases": cases, "seconds": round(elapsed, 1),
              "stats": stats, "findings": list(findings.values())}
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nDone in {elapsed:.1f}s. Stats: {stats}")
    print(f"Unique findings: {len(findings)}  ->  saved to {out_path}")
    for fd in findings.values():
        print(f"  {fd['type']:6s} service {fd['service']}  req=[{fd['request']}]  "
              f"setup={fd['setup']}  hits={fd['hits']}")
    return report


def replay(setup_hex, req_hex):
    ecu = FakeECU(channel=CHANNEL)
    ecu.start()
    tester = Tester()
    setup = [parse_hex(setup_hex)] if setup_hex else []
    kind, resp, detail = run_case(tester, setup, parse_hex(req_hex))
    print(f"Replay req=[{req_hex}] setup={setup_hex or 'none'} -> "
          f"{kind or 'no bug'}  resp={hexs(resp) if resp else None}  {detail}")
    ecu.stop()
    tester.bus.shutdown()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="UDS fuzzer (simulation only)")
    ap.add_argument("--cases", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default="findings.json")
    ap.add_argument("--replay", help='request bytes in hex, e.g. "27 02 00 00"')
    ap.add_argument("--setup", help='optional setup request, e.g. "10 03"')
    a = ap.parse_args()
    if a.replay:
        replay(a.setup, a.replay)
    else:
        fuzz(a.cases, a.seed, a.out)
