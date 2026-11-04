import struct
import unittest

from helpers import CLIENT, PEER, FakeLink, arp, quiet_report
from test_core import required
from netprobe.wire import build_ipv4, checksum, ip_text, parse_ipv4
from netprobe.report import ProbeError, ProbeTimeout


class PingTests(unittest.TestCase):
    def setUp(self):
        self.p = required("netprobe.ping")

    def echo_peer(self, link, frame):
        if frame.ethertype == 0x0806:
            if struct.unpack_from("!H", frame.payload, 6)[0] == 1:
                target = ip_text(frame.payload[24:28])
                if target == "192.0.2.1":
                    link.push(0x0806, arp(2, PEER, target, CLIENT, "192.0.2.10"))
        elif frame.ethertype == 0x0800:
            ip = parse_ipv4(frame.payload)
            echo = b"\0\0\0\0" + ip.payload[4:]
            echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
            link.push(0x0800, build_ipv4(ip.dst, ip.src, 1, echo))

    def test_cross_subnet_arp_gateway_and_echo_stats(self):
        link = FakeLink(self.echo_peer)
        result = self.p.run_ping(link, "192.0.2.10", "198.51.100.1", "255.255.255.0",
                                 "192.0.2.1", 3, 0.1, 0.2, 32, quiet_report())
        self.assertEqual((result["sent"], result["received"], result["loss_percent"]), (3, 3, 0))
        self.assertAlmostEqual(result["rtt_avg_ms"], 10)
        requests = [f for f in link.sent if f.ethertype == 0x0806 and ip_text(f.payload[24:28]) == "192.0.2.1"]
        self.assertEqual(len(requests), 1)
        self.assertTrue(all(f.dst == PEER for f in link.sent if f.ethertype == 0x0800))

    def test_arp_retry_and_timeout(self):
        link = FakeLink()
        channel = self.p.EthernetIPv4(link, "192.0.2.10", "255.255.255.0", None, quiet_report(), .1, 2)
        with self.assertRaises(ProbeTimeout):
            channel.resolve("192.0.2.1")
        self.assertEqual(len(link.sent), 3)
        self.assertAlmostEqual(link.now, .3)

    def test_wrong_echo_payload_cannot_pass(self):
        def peer(link, frame):
            if frame.ethertype == 0x0806:
                self.echo_peer(link, frame)
                return
            ip = parse_ipv4(frame.payload)
            echo = b"\0\0\0\0" + ip.payload[4:8] + b"wrong"
            echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
            link.push(0x0800, build_ipv4(ip.dst, ip.src, 1, echo))
        result = self.p.run_ping(FakeLink(peer), "192.0.2.10", "192.0.2.1", "255.255.255.0",
                                 None, 1, .1, .2, 32, quiet_report())
        self.assertEqual(result["received"], 0)
        self.assertFalse(result["success"])

    def test_answer_arp_for_test_address(self):
        link = FakeLink()
        channel = self.p.EthernetIPv4(link, "192.0.2.10", "255.255.255.0", None, quiet_report())
        link.push(0x0806, arp(1, PEER, "192.0.2.1", "00:00:00:00:00:00", "192.0.2.10"))
        self.assertIsNone(channel.recv_ip(.1))
        self.assertEqual(struct.unpack_from("!H", link.sent[0].payload, 6)[0], 2)
        self.assertEqual(link.sent[0].dst, PEER)

    def test_conflict_detection(self):
        def peer(link, frame):
            link.push(0x0806, arp(2, PEER, "192.0.2.10", CLIENT, "0.0.0.0"))
        channel = self.p.EthernetIPv4(FakeLink(peer), "192.0.2.10", "255.255.255.0", None, quiet_report())
        with self.assertRaisesRegex(ProbeError, "conflict"):
            channel.probe_address()

    def test_missing_gateway_and_oversize_fail(self):
        channel = self.p.EthernetIPv4(FakeLink(), "192.0.2.10", "255.255.255.0", None, quiet_report())
        with self.assertRaises(ValueError):
            channel.next_hop("198.51.100.1")
        with self.assertRaises(ValueError):
            self.p.echo(channel, "192.0.2.1", 1, .1, .1, 1473, quiet_report())


if __name__ == "__main__":
    unittest.main()
