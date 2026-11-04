import struct
import unittest

from helpers import CLIENT, PEER, FakeLink, arp, quiet_report
from netprobe.ping import EthernetIPv4, echo
from netprobe.report import ProbeTimeout
from netprobe.wire import build_ipv4, checksum, ip_text, parse_ipv4


class PingEdgeTests(unittest.TestCase):
    def channel(self, peer):
        link = FakeLink(peer)
        channel = EthernetIPv4(link, "192.0.2.10", "255.255.255.0", None, quiet_report(), .1, 0)
        channel.cache["192.0.2.1"] = PEER
        return channel

    def reply(self, request, wrong_id=False):
        data = bytearray(b"\0\0\0\0" + request[4:])
        if wrong_id:
            data[4] ^= 1
        data[2:4] = struct.pack("!H", checksum(bytes(data)))
        return bytes(data)

    def test_duplicate_and_late_replies_not_counted_twice(self):
        def peer(link, frame):
            ip = parse_ipv4(frame.payload)
            seq = struct.unpack_from("!H", ip.payload, 6)[0]
            if seq == 1:
                answer = build_ipv4(ip.dst, ip.src, 1, self.reply(ip.payload))
                link.push(0x0800, answer)
                link.push(0x0800, answer, delay=.12)
        result = echo(self.channel(peer), "192.0.2.1", 2, .1, .2, 32, quiet_report())
        self.assertEqual((result["received"], result["loss_percent"]), (1, 50))

    def test_incorrect_identifier_does_not_count(self):
        def peer(link, frame):
            ip = parse_ipv4(frame.payload)
            link.push(0x0800, build_ipv4(ip.dst, ip.src, 1, self.reply(ip.payload, wrong_id=True)))
        result = echo(self.channel(peer), "192.0.2.1", 1, .1, .2, 32, quiet_report())
        self.assertEqual(result["received"], 0)

    def test_unreachable_quote_matches_only_this_request(self):
        def peer(link, frame):
            data = b"\x03\x01\0\0\0\0\0\0" + frame.payload[:28]
            data = data[:2] + struct.pack("!H", checksum(data)) + data[4:]
            link.push(0x0800, build_ipv4("192.0.2.254", "192.0.2.10", 1, data))
        result = echo(self.channel(peer), "192.0.2.1", 1, .1, .2, 32, quiet_report())
        self.assertEqual(result["icmp_errors"], 1)
        self.assertEqual(result["received"], 0)

    def test_noise_does_not_extend_arp_deadline(self):
        link = FakeLink()
        for n in range(1, 21):
            link.push(0x0806, arp(2, PEER, "192.0.2.99", CLIENT, "192.0.2.10"), delay=n * .01)
        channel = EthernetIPv4(link, "192.0.2.10", "255.255.255.0", None, quiet_report(), .1, 0)
        with self.assertRaises(ProbeTimeout):
            channel.resolve("192.0.2.1")
        self.assertAlmostEqual(link.now, .1)


if __name__ == "__main__":
    unittest.main()
