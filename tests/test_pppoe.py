import hashlib
import struct
import unittest
from types import SimpleNamespace

from helpers import FakeLink, quiet_report
from test_core import required
from netprobe.report import ProbeError, ProbeTimeout
from netprobe.wire import build_ipv4, checksum, ip_bytes, parse_ipv4

LCP, IPCP, PAP, CHAP = 0xc021, 0x8021, 0xc023, 0xc223


def tag(kind, value):
    return struct.pack("!HH", kind, len(value)) + value


def tags(raw):
    out = {}
    while raw:
        kind, size = struct.unpack_from("!HH", raw)
        out[kind], raw = raw[4:4 + size], raw[4 + size:]
    return out


def control(code, ident, data=b""):
    return struct.pack("!BBH", code, ident, len(data) + 4) + data


def encap(code, sid, data):
    return struct.pack("!BBHH", 0x11, code, sid, len(data)) + data


def opts(**changes):
    values = dict(timeout=.1, retries=2, username="tester", password="secret", service="",
                  ac_name=None, ping="198.51.100.1", count=2, interval=.1, size=32)
    values.update(changes)
    return SimpleNamespace(**values)


class AccessConcentrator:
    def __init__(self, auth="pap", failure=False, bad_ack=False, terminate=False, dns_reject=False):
        self.auth, self.failure, self.bad_ack = auth, failure, bad_ack
        self.terminate, self.dns_reject = terminate, dns_reject
        self.sent_lcp = self.sent_ipcp = self.sent_challenge = False
        self.padr = self.auth_data = None
        self.peer_lcp_ack = self.peer_ipcp_ack = False
        self.padt = self.terminated = False
        self.ipcp_requests = []

    def push(self, link, proto, data):
        link.push(0x8864, encap(0, 0x1234, struct.pack("!H", proto) + data))

    def challenge(self, link):
        self.sent_challenge = True
        self.push(link, CHAP, control(1, 73, b"\x10" + b"0123456789abcdef" + b"test-ac"))

    def __call__(self, link, frame):
        ver, code, sid, size = struct.unpack_from("!BBHH", frame.payload)
        data = frame.payload[6:6 + size]
        if frame.ethertype == 0x8863:
            parsed = tags(data)
            if code == 9:
                self.host = parsed[0x0103]
                response = tag(0x0101, b"") + tag(0x0102, b"test-ac") + tag(0x0103, self.host)
                response += tag(0x0104, b"cookie") + tag(0x0110, b"relay")
                link.push(0x8863, encap(7, 0, response))
            elif code == 0x19:
                self.padr = parsed
                link.push(0x8863, encap(0x65, 0x1234, tag(0x0101, b"") + tag(0x0103, self.host)))
            elif code == 0xa7:
                self.padt = True
            return
        proto = struct.unpack_from("!H", data)[0]
        data = data[2:]
        if proto == 0x0021:
            if self.terminate:
                link.push(0x8863, encap(0xa7, 0x1234, b""))
                return
            ip = parse_ipv4(data)
            echo = b"\0\0\0\0" + ip.payload[4:]
            echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
            self.push(link, LCP, control(9, 90, struct.pack("!I", 0xabcdef01)))
            self.push(link, 0x0021, build_ipv4(ip.dst, ip.src, 1, echo))
            return
        code, ident, size = struct.unpack_from("!BBH", data)
        payload = data[4:size]
        if proto == LCP:
            if code == 1:
                self.push(link, LCP, control(2, ident, payload + b"\x07\x02" if self.bad_ack else payload))
                if not self.sent_lcp:
                    self.sent_lcp = True
                    auth = {"pap": b"\x03\x04\xc0\x23", "chap": b"\x03\x05\xc2\x23\x05",
                            "mschap": b"\x03\x05\xc2\x23\x81", "none": b""}[self.auth]
                    self.peer_lcp = b"\x01\x04\x05\xd4" + auth + b"\x05\x06\xab\xcd\xef\x01"
                    self.push(link, LCP, control(1, 42, self.peer_lcp))
            elif code == 2 and ident == 42:
                self.peer_lcp_ack = payload == self.peer_lcp
                if self.auth == "chap" and not self.sent_challenge:
                    self.challenge(link)
            elif code == 5:
                self.terminated = True
                self.push(link, LCP, control(6, ident, payload))
        elif proto == PAP and code == 1:
            self.auth_data = payload
            self.push(link, PAP, control(3 if self.failure else 2, ident, b"\x02ok"))
        elif proto == CHAP and code == 2:
            self.auth_data = payload
            self.push(link, CHAP, control(4 if self.failure else 3, ident, b"done"))
        elif proto == IPCP:
            if code == 1:
                self.ipcp_requests.append(payload)
                if b"\x03\x06\0\0\0\0" in payload:
                    self.push(link, IPCP, control(3, ident, b"\x03\x06" + ip_bytes("192.0.2.10")))
                elif self.dns_reject and b"\x81\x06" in payload:
                    self.push(link, IPCP, control(4, ident, b"\x81\x06\0\0\0\0\x83\x06\0\0\0\0"))
                else:
                    self.push(link, IPCP, control(2, ident, payload))
                if not self.sent_ipcp:
                    self.sent_ipcp = True
                    self.push(link, IPCP, control(1, 55, b"\x03\x06" + ip_bytes("192.0.2.1")))
            elif code == 2 and ident == 55:
                self.peer_ipcp_ack = payload == b"\x03\x06" + ip_bytes("192.0.2.1")


class PppoeTests(unittest.TestCase):
    def setUp(self):
        self.p = required("netprobe.pppoe")

    def test_full_pap_flow_echo_termination_and_discovery_tags(self):
        ac, report = AccessConcentrator(), quiet_report()
        result = self.p.run_pppoe(FakeLink(ac), opts(), report)
        self.assertTrue(result["success"])
        self.assertEqual(result["ip"], "192.0.2.10")
        self.assertEqual(result["peer_ip"], "192.0.2.1")
        self.assertEqual(result["ping"]["received"], 2)
        self.assertEqual(ac.padr[0x0104], b"cookie")
        self.assertEqual(ac.padr[0x0110], b"relay")
        self.assertEqual(ac.auth_data, b"\x06tester\x06secret")
        self.assertTrue(ac.peer_lcp_ack and ac.peer_ipcp_ack and ac.padt and ac.terminated)
        self.assertNotIn("secret", report.stream.getvalue())
        self.assertNotIn("secret", str(report.data))

    def test_chap_md5_digest(self):
        ac = AccessConcentrator(auth="chap")
        result = self.p.run_pppoe(FakeLink(ac), opts(), quiet_report())
        digest = hashlib.md5(b"\x49secret0123456789abcdef").digest()
        self.assertEqual(ac.auth_data, b"\x10" + digest + b"tester")
        self.assertTrue(result["success"])

    def test_no_auth_and_dns_reject(self):
        ac = AccessConcentrator(auth="none", dns_reject=True)
        result = self.p.run_pppoe(FakeLink(ac), opts(), quiet_report())
        self.assertTrue(result["success"])
        self.assertEqual(ac.ipcp_requests[-1], b"\x03\x06\xc0\x00\x02\x0a")

    def test_auth_failure_still_padt(self):
        ac = AccessConcentrator(failure=True)
        with self.assertRaisesRegex(ProbeError, "authentication"):
            self.p.run_pppoe(FakeLink(ac), opts(), quiet_report())
        self.assertTrue(ac.padt)
        self.assertEqual(ac.ipcp_requests, [])

    def test_unsupported_auth_explicit_failure(self):
        ac = AccessConcentrator(auth="mschap")
        with self.assertRaisesRegex(ProbeError, "Unsupported"):
            self.p.run_pppoe(FakeLink(ac), opts(), quiet_report())
        self.assertTrue(ac.padt)

    def test_inexact_lcp_ack_does_not_open(self):
        ac = AccessConcentrator(bad_ack=True)
        link = FakeLink(ac)
        with self.assertRaises(ProbeTimeout):
            self.p.run_pppoe(link, opts(), quiet_report())
        self.assertTrue(ac.padt)
        self.assertLess(link.now, 5)
        self.assertEqual(ac.ipcp_requests, [])

    def test_remote_padt_stops_ping(self):
        ac = AccessConcentrator(terminate=True)
        with self.assertRaisesRegex(ProbeError, "PADT"):
            self.p.run_pppoe(FakeLink(ac), opts(), quiet_report())

    def test_malformed_lengths_are_rejected(self):
        self.assertIsNone(self.p.parse_envelope(b"\x11\x07\0\0\0\x10oops"))
        self.assertIsNone(self.p.parse_control(b"\x01\x01\0\x10oops"))
        with self.assertRaises(ValueError):
            self.p.parse_options(b"\x01\x01")


if __name__ == "__main__":
    unittest.main()
