"""
Fake car computer (ECU) that speaks a small part of UDS (ISO 14229).

It listens for requests on CAN ID 0x7E0 and replies on 0x7E8, using
ISO-TP "single frames" only (byte 0 = payload length, max 7 bytes).

THREE BUGS ARE PLANTED ON PURPOSE (this is a training target):
  BUG 1 (crash):  0x22 ReadDataByIdentifier with only ONE DID byte
                  -> code reads a byte that isn't there and the ECU dies.
  BUG 2 (hang):   0x31 RoutineControl start, routine 0xFF00
                  -> a "debug routine" blocks the ECU for 3 seconds.
  BUG 3 (bypass): 0x27 SecurityAccess sendKey with an all-zero key
                  -> a leftover factory backdoor unlocks the ECU.

Simulation only. Never point the fuzzer at a real vehicle.
"""
import os
import threading
import time

import can

REQ_ID = 0x7E0
RESP_ID = 0x7E8

# Negative Response Codes (NRCs): the ECU's way of saying "no, because..."
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNC_NOT_SUPPORTED = 0x12
NRC_INCORRECT_LENGTH = 0x13
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_SEQUENCE_ERROR = 0x24
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_SECURITY_ACCESS_DENIED = 0x33
NRC_INVALID_KEY = 0x35

SECRET_XOR = 0x5A5A  # the "real" key algorithm: key = seed XOR 0x5A5A


class FakeECU:
    def __init__(self, channel="uds_lab", interface="virtual"):
        self.bus = can.Bus(interface=interface, channel=channel, receive_own_messages=False)
        self.thread = None
        self.running = False
        self.reset_state()
        self.dids = {
            0xF190: b"1HGCM826",          # VIN (shortened to fit a single frame)
            0xF18C: b"ECU-0042",          # serial number
            0xF1A0: b"FW1.2.3",           # firmware version
        }
        self.protected_dids = {0xF1F0: b"SECRET!"}  # needs security unlock

    def reset_state(self):
        self.session = 0x01          # 0x01 default, 0x02 programming, 0x03 extended
        self.unlocked = False
        self.last_seed = None

    # ---------- lifecycle ----------
    def start(self):
        self.reset_state()
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.bus.shutdown()

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def _loop(self):
        # No try/except around handle(): an unhandled error kills the ECU,
        # just like a real firmware fault. That's what BUG 1 relies on.
        while self.running:
            msg = self.bus.recv(timeout=0.05)
            if msg is None or msg.arbitration_id != REQ_ID:
                continue
            data = bytes(msg.data)
            if not data:
                continue
            length = data[0] & 0x0F
            payload = data[1:1 + length]
            if not payload:
                continue
            reply = self.handle(payload)
            if reply is not None:
                self._send(reply)

    def _send(self, payload):
        frame = bytes([len(payload)]) + payload
        frame = frame.ljust(8, b"\x00")
        self.bus.send(can.Message(arbitration_id=RESP_ID, data=frame, is_extended_id=False))

    @staticmethod
    def neg(sid, nrc):
        return bytes([0x7F, sid, nrc])

    # ---------- UDS services ----------
    def handle(self, p):
        sid = p[0]
        if sid == 0x10:
            return self.diag_session(p)
        if sid == 0x11:
            return self.ecu_reset(p)
        if sid == 0x22:
            return self.read_did(p)
        if sid == 0x27:
            return self.security_access(p)
        if sid == 0x31:
            return self.routine_control(p)
        if sid == 0x3E:
            return self.tester_present(p)
        return self.neg(sid, NRC_SERVICE_NOT_SUPPORTED)

    def diag_session(self, p):
        if len(p) != 2:
            return self.neg(0x10, NRC_INCORRECT_LENGTH)
        if p[1] not in (0x01, 0x02, 0x03):
            return self.neg(0x10, NRC_SUBFUNC_NOT_SUPPORTED)
        self.session = p[1]
        self.unlocked = False
        return bytes([0x50, p[1]])

    def ecu_reset(self, p):
        if len(p) != 2:
            return self.neg(0x11, NRC_INCORRECT_LENGTH)
        if p[1] not in (0x01, 0x03):
            return self.neg(0x11, NRC_SUBFUNC_NOT_SUPPORTED)
        self.reset_state()
        return bytes([0x51, p[1]])

    def read_did(self, p):
        if len(p) < 2:
            return self.neg(0x22, NRC_INCORRECT_LENGTH)
        # BUG 1: should check len(p) >= 3. With one DID byte, p[2] doesn't exist
        # and this raises IndexError, which kills the ECU loop.
        did = (p[1] << 8) | p[2]
        if did in self.dids:
            return bytes([0x62, p[1], p[2]]) + self.dids[did][:4]
        if did in self.protected_dids:
            if not self.unlocked:
                return self.neg(0x22, NRC_SECURITY_ACCESS_DENIED)
            return bytes([0x62, p[1], p[2]]) + self.protected_dids[did][:4]
        return self.neg(0x22, NRC_REQUEST_OUT_OF_RANGE)

    def security_access(self, p):
        if len(p) < 2:
            return self.neg(0x27, NRC_INCORRECT_LENGTH)
        if self.session == 0x01:
            return self.neg(0x27, NRC_CONDITIONS_NOT_CORRECT)
        sub = p[1]
        if sub == 0x01:  # requestSeed
            if len(p) != 2:
                return self.neg(0x27, NRC_INCORRECT_LENGTH)
            seed = int.from_bytes(os.urandom(2), "big") or 1
            self.last_seed = seed
            return bytes([0x67, 0x01]) + seed.to_bytes(2, "big")
        if sub == 0x02:  # sendKey
            if len(p) != 4:
                return self.neg(0x27, NRC_INCORRECT_LENGTH)
            key = (p[2] << 8) | p[3]
            # BUG 3: leftover factory backdoor. Key 0x0000 always works,
            # even if no seed was ever requested.
            if key == 0x0000:
                self.unlocked = True
                return bytes([0x67, 0x02])
            if self.last_seed is None:
                return self.neg(0x27, NRC_REQUEST_SEQUENCE_ERROR)
            if key == (self.last_seed ^ SECRET_XOR):
                self.unlocked = True
                self.last_seed = None
                return bytes([0x67, 0x02])
            self.last_seed = None
            return self.neg(0x27, NRC_INVALID_KEY)
        return self.neg(0x27, NRC_SUBFUNC_NOT_SUPPORTED)

    def routine_control(self, p):
        if len(p) < 4:
            return self.neg(0x31, NRC_INCORRECT_LENGTH)
        sub, rid = p[1], (p[2] << 8) | p[3]
        if sub not in (0x01, 0x02, 0x03):
            return self.neg(0x31, NRC_SUBFUNC_NOT_SUPPORTED)
        if rid == 0xFF00 and sub == 0x01:
            # BUG 2: forgotten debug routine that blocks the ECU.
            time.sleep(3)
            return bytes([0x71, sub, p[2], p[3]])
        if rid == 0x0203:  # a normal routine, e.g. "check memory"
            return bytes([0x71, sub, p[2], p[3], 0x00])
        return self.neg(0x31, NRC_REQUEST_OUT_OF_RANGE)

    def tester_present(self, p):
        if len(p) != 2 or p[1] not in (0x00, 0x80):
            return self.neg(0x3E, NRC_SUBFUNC_NOT_SUPPORTED)
        if p[1] == 0x80:  # "suppress positive response"
            return None
        return bytes([0x7E, 0x00])


if __name__ == "__main__":
    ecu = FakeECU()
    ecu.start()
    print("Fake ECU running on virtual bus 'uds_lab' (Ctrl+C to stop)")
    try:
        while ecu.is_alive():
            time.sleep(0.5)
        print("ECU died!")
    except KeyboardInterrupt:
        pass
    finally:
        ecu.stop()
