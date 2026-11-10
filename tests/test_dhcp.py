import struct
import unittest
from types import SimpleNamespace

from helpers import CLIENT, PEER, FakeLink, arp, quiet_report
from test_core import required
from netprobe.wire import build_ipv4, build_udp, ip_bytes, ip_text, mac_bytes, parse_ipv4, parse_udp
from netprobe.report import ProbeError


def options(**changes):
    values = dict(timeout=.1, retries=1, renew_delay=0, hostname="test-host", ping=None,
                  count=1, interval=.1, size=32, broadcast=False)
    values.update(changes)
    return SimpleNamespace(**values)


def decode_options(data):
    result, pos = {}, 240
    while pos < len(data):
        code = data[pos]
        pos += 1
        if code == 255:
            break
        if code == 0:
            continue
        length = data[pos]
        pos += 1
        result[code] = data[pos:pos + length]
        pos += length
    return result


def reply(request, msg, server="192.0.2.1", wrong_xid=False):
    header = bytearray(request[:236])
    header[0] = 2
    if wrong_xid:
        header[4] ^= 1
    header[16:20] = ip_bytes("192.0.2.10")
    opts = [(53, bytes([msg])), (54, ip_bytes(server)), (1, ip_bytes("255.255.255.0")),
            (3, ip_bytes(server)), (6, ip_bytes(server)), (51, struct.pack("!I", 3600))]
    data = bytes(header) + b"\x63\x82\x53\x63" + b"".join(bytes([k, len(v)]) + v for k, v in opts) + b"\xff"
    return build_ipv4(server, "255.255.255.255", 17, build_udp(server, "255.255.255.255", 67, 68, data))


class Server:
    def __init__(self, rebind=False, nak=False, conflict=False, interrupt=False):
        self.rebind, self.nak, self.conflict, self.interrupt = rebind, nak, conflict, interrupt
        self.requests = []

    def __call__(self, link, frame):
        if frame.ethertype == 0x0806:
            target = ip_text(frame.payload[24:28])
            if target == "192.0.2.1" or (self.conflict and target == "192.0.2.10"):
                link.push(0x0806, arp(2, PEER, target, CLIENT, ip_text(frame.payload[14:18])))
            return
        ip = parse_ipv4(frame.payload)
        udp = parse_udp(ip)
        if not udp:
            return
        data = udp[2]
        opts = decode_options(data)
        kind = opts[53][0]
        self.requests.append((kind, ip, data, opts, frame.dst))
        if kind == 1:
            link.push(0x0800, reply(data, 2, wrong_xid=True))
            link.push(0x0800, reply(data, 2))
        elif kind == 3:
            renewing = data[12:16] != b"\0" * 4
            if renewing and self.interrupt:
                raise KeyboardInterrupt()
            if renewing and self.rebind and ip.dst != "255.255.255.255":
                return
            link.push(0x0800, reply(data, 6 if renewing and self.nak else 5,
                                    "192.0.2.2" if renewing and self.rebind else "192.0.2.1"))


class DhcpTests(unittest.TestCase):
    def setUp(self):
        self.d = required("netprobe.dhcp")

    def test_dora_renew_release_fields(self):
        server = Server()
        result = self.d.run_dhcp(FakeLink(server), options(), quiet_report())
        self.assertTrue(result["success"])
        self.assertTrue(result["release_sent"])
        self.assertEqual(result["lease"]["ip"], "192.0.2.10")
        self.assertEqual([r[0] for r in server.requests], [1, 3, 3, 7])
        selecting, renewing, release = server.requests[1:]
        self.assertEqual(selecting[3][50], ip_bytes("192.0.2.10"))
        self.assertEqual(selecting[3][54], ip_bytes("192.0.2.1"))
        self.assertEqual(renewing[2][12:16], ip_bytes("192.0.2.10"))
        self.assertNotIn(50, renewing[3])
        self.assertNotIn(54, renewing[3])
        self.assertEqual(renewing[1].dst, "192.0.2.1")
        self.assertEqual(renewing[4], PEER)
        self.assertEqual(release[3][54], ip_bytes("192.0.2.1"))
        self.assertEqual(release[3][61], b"\x01" + mac_bytes(CLIENT))

    def test_reply_broadcast_flag_is_opt_in_for_discover_and_requests(self):
        for broadcast, flags in ((False, 0), (True, 0x8000)):
            with self.subTest(broadcast=broadcast):
                server = Server(rebind=True)
                result = self.d.run_dhcp(FakeLink(server), options(broadcast=broadcast), quiet_report())
                self.assertEqual(result["lease"]["server"], "192.0.2.2")
                for kind, ip, data, opts, destination in server.requests:
                    expected = flags if kind in (1, 3) and ip.dst == "255.255.255.255" else 0
                    self.assertEqual(struct.unpack_from("!H", data, 10)[0], expected)
                self.assertEqual(server.requests[0][1].dst, "255.255.255.255")
                self.assertEqual(server.requests[0][4], "ff:ff:ff:ff:ff:ff")

    def test_renew_timeout_rebind_changes_server(self):
        server = Server(rebind=True)
        result = self.d.run_dhcp(FakeLink(server), options(), quiet_report())
        self.assertEqual(result["lease"]["server"], "192.0.2.2")
        self.assertTrue(any(r[0] == 3 and r[1].src == "192.0.2.10" and r[1].dst == "255.255.255.255"
                            for r in server.requests))

    def test_nak_invalidates_lease_without_release(self):
        server = Server(nak=True)
        with self.assertRaisesRegex(ProbeError, "NAK"):
            self.d.run_dhcp(FakeLink(server), options(), quiet_report())
        self.assertNotIn(7, [r[0] for r in server.requests])

    def test_conflict_declines_without_releasing(self):
        server = Server(conflict=True)
        with self.assertRaisesRegex(ProbeError, "conflict"):
            self.d.run_dhcp(FakeLink(server), options(), quiet_report())
        self.assertEqual([r[0] for r in server.requests], [1, 3, 4])

    def test_interrupt_still_releases(self):
        server = Server(interrupt=True)
        with self.assertRaises(KeyboardInterrupt):
            self.d.run_dhcp(FakeLink(server), options(), quiet_report())
        self.assertEqual(server.requests[-1][0], 7)

    def test_failed_ping_still_releases(self):
        server = Server()
        result = self.d.run_dhcp(FakeLink(server), options(ping="192.0.2.1"), quiet_report())
        self.assertFalse(result["success"])
        self.assertEqual(server.requests[-1][0], 7)

    def test_wrong_client_and_server_ack_do_not_advance_state(self):
        class NoisyServer(Server):
            def __call__(self, link, frame):
                if frame.ethertype == 0x0800:
                    ip = parse_ipv4(frame.payload)
                    udp = parse_udp(ip)
                    if udp and decode_options(udp[2]).get(53) == b"\x03":
                        request = udp[2]
                        wrong_client = bytearray(request)
                        wrong_client[28] ^= 2
                        link.push(0x0800, reply(bytes(wrong_client), 6), delay=.001)
                        link.push(0x0800, reply(request, 6, server="192.0.2.99"), delay=.002)
                super().__call__(link, frame)
        result = self.d.run_dhcp(FakeLink(NoisyServer()), options(), quiet_report())
        self.assertTrue(result["success"])
        self.assertEqual(result["lease"]["server"], "192.0.2.1")

    def test_malformed_option_and_wrong_client_are_ignored(self):
        self.assertIsNone(self.d.parse_message(b"\0" * 240))
        server = Server()
        link = FakeLink(server)
        self.d.run_dhcp(link, options(), quiet_report())
        data = server.requests[0][2]
        raw = bytearray(reply(data, 2))
        packet = parse_udp(parse_ipv4(bytes(raw)))[2]
        self.assertIsNone(self.d.parse_message(packet[:240] + b"\x35\x08\x02"))


if __name__ == "__main__":
    unittest.main()
