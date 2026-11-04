import importlib
import io
import json
import tempfile
import unittest
from pathlib import Path


def required(name):
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        raise AssertionError(f"Implementation missing: {name}") from exc


class WireTests(unittest.TestCase):
    def setUp(self):
        self.wire = required("netprobe.wire")

    def test_vlan_frame_exact_bytes_and_filter(self):
        w = self.wire
        raw = w.encode_frame("02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 0x0806, b"arp", 100, 5)
        self.assertEqual(raw[:18].hex(), "ffffffffffff0200000000018100a0640806")
        frame = w.decode_frame(raw)
        self.assertEqual((frame.vlan, frame.pcp, frame.ethertype, frame.payload), (100, 5, 0x0806, b"arp"))
        self.assertTrue(w.accept_frame(frame, "02:00:00:00:00:02", 100))
        self.assertFalse(w.accept_frame(frame, "02:00:00:00:00:02", None))
        self.assertFalse(w.accept_frame(frame, "02:00:00:00:00:02", 101))
        self.assertFalse(w.accept_frame(frame, "02:00:00:00:00:01", 100))

    def test_reject_truncated_and_nested_vlan(self):
        w = self.wire
        self.assertIsNone(w.decode_frame(b"\x00" * 13))
        self.assertIsNone(w.decode_frame(bytes.fromhex("ffffffffffff02000000000181000064")))
        self.assertIsNone(w.decode_frame(bytes.fromhex("ffffffffffff02000000000181000064810000010800")))

    def test_reject_invalid_mac_vlan_pcp(self):
        for mac in ("ff:ff:ff:ff:ff:ff", "01:00:00:00:00:01", "00:00:00:00:00:00", "bad"):
            with self.assertRaises(ValueError):
                self.wire.validate_mac(mac)
        for vlan, pcp in ((0, 0), (4095, 0), (1, 8), (None, 1)):
            with self.assertRaises(ValueError):
                self.wire.encode_frame("02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 0x0800, b"", vlan, pcp)

    def test_ipv4_checksums_length_fragments(self):
        w = self.wire
        packet = w.build_ipv4("192.0.2.1", "192.0.2.2", 1, b"payload")
        self.assertEqual(w.checksum(packet[:20]), 0)
        ip = w.parse_ipv4(packet + b"ethernet padding")
        self.assertEqual((ip.src, ip.dst, ip.protocol, ip.payload), ("192.0.2.1", "192.0.2.2", 1, b"payload"))
        self.assertIsNone(w.parse_ipv4(packet[:-1]))
        corrupt = bytearray(packet)
        corrupt[12] ^= 1
        self.assertIsNone(w.parse_ipv4(bytes(corrupt)))

    def test_interface_selection_uses_windows_index_not_position(self):
        t = required("netprobe.transport")
        a = t.Interface(9, "以太网", "Realtek", "{AAA}", "24:6a:0e:74:84:6f", "Up", 1500)
        b = t.Interface(7, "以太网 3", "Realtek", "{BBB}", "80:ea:07:87:1a:93", "Up", 1500)
        self.assertEqual(t.select_interface([a, b], "7"), b)
        self.assertEqual(t.select_interface([a, b], "以太网"), a)
        self.assertEqual(t.select_interface([a, b], "\\Device\\NPF_{bbb}"), b)
        with self.assertRaises(ValueError):
            t.select_interface([a, b], "Realtek")
        with self.assertRaises(ValueError):
            t.select_interface([a, b], "1")

    def test_report_json_and_control_character_escaping(self):
        r = required("netprobe.report")
        stream = io.StringIO()
        report = r.Report("ping", stream=stream)
        report.event("ARP", "RX", "peer", name="bad\x1b[31m\npeer")
        report.finish(True, {"received": 1})
        self.assertNotIn("\x1b", stream.getvalue())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.json"
            report.save(path)
            result = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(result["success"])
        self.assertEqual(result["result"]["received"], 1)


if __name__ == "__main__":
    unittest.main()
