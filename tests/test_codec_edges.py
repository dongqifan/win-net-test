import struct
import unittest

from netprobe.wire import build_ipv4, build_udp, checksum, parse_ipv4, parse_udp
from netprobe.dhcp import parse_message
from netprobe.pppoe import parse_control, parse_envelope, parse_options, parse_tags


class CodecEdgeTests(unittest.TestCase):
    def test_ipv4_fragment_rejected_even_with_valid_checksum(self):
        raw = bytearray(build_ipv4("192.0.2.1", "192.0.2.2", 1, b"12345678"))
        raw[6:8] = b"\x20\x00"
        raw[10:12] = b"\0\0"
        raw[10:12] = struct.pack("!H", checksum(bytes(raw[:20])))
        self.assertIsNone(parse_ipv4(bytes(raw)))

    def test_udp_corruption_detected(self):
        udp = bytearray(build_udp("192.0.2.1", "192.0.2.2", 67, 68, b"test"))
        good = parse_ipv4(build_ipv4("192.0.2.1", "192.0.2.2", 17, bytes(udp)))
        self.assertEqual(parse_udp(good), (67, 68, b"test"))
        udp[-1] ^= 1
        bad = parse_ipv4(build_ipv4("192.0.2.1", "192.0.2.2", 17, bytes(udp)))
        self.assertIsNone(parse_udp(bad))

    def test_dhcp_option_overload_from_boot_file(self):
        raw = bytearray(240)
        raw[:3] = b"\x02\x01\x06"
        raw[236:] = b"\x63\x82\x53\x63"
        raw[108:115] = b"\x36\x04\xc0\x00\x02\x01\xff"
        raw += b"\x35\x01\x05\x34\x01\x01\xff"
        msg = parse_message(bytes(raw))
        self.assertEqual(msg.options[54], b"\xc0\x00\x02\x01")

    def test_ppp_duplicate_and_truncated_options(self):
        for raw in (b"\x01", b"\x01\x00", b"\x01\x04\0", b"\x07\x02\x07\x02"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_options(raw)
        self.assertEqual(parse_options(b"\x01\x04\x05\xd4"), [(1, b"\x01\x04\x05\xd4")])

    def test_pppoe_tags_and_padding(self):
        self.assertEqual(parse_envelope(b"\x11\x65\x12\x34\0\x04abcdpadding"), (0x65, 0x1234, b"abcd"))
        self.assertEqual(parse_control(b"\x02\x07\0\x04padding"), (2, 7, b""))
        for raw in (b"\0", b"\x01\x03\0\x04x", b"\0\0\0\x01x"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_tags(raw)


if __name__ == "__main__":
    unittest.main()
