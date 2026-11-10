import io
import json
import struct
import sys
import unittest
from types import SimpleNamespace

from helpers import CLIENT, PEER, FakeLink, arp, quiet_report
from test_core import required
from netprobe.report import ProbeError, ProbeTimeout, Report
from netprobe.wire import checksum, parse_ipv4, parse_udp


def options(**changes):
    values = dict(protocol="dhcp", interval_ms=100, count=4, hostname="win-net-test",
                  service="", src_ip="192.0.2.10", netmask="24", gateway=None,
                  target="192.0.2.1", dst_mac=None, size=32, timeout=.1, retries=0, broadcast=False)
    values.update(changes)
    return SimpleNamespace(**values)


class TimedLink(FakeLink):
    def __init__(self, peer=None, send_cost=0):
        super().__init__(peer)
        self.starts, self.send_cost = [], send_cost

    def send(self, kind, payload, dst):
        self.starts.append(self.now)
        super().send(kind, payload, dst)
        self.now += self.send_cost


class RepeatTests(unittest.TestCase):
    def setUp(self):
        self.repeat = required("netprobe.repeat")

    def test_discover_keeps_client_identity_without_requesting_lease(self):
        link = TimedLink()
        result = self.repeat.run_repeat(link, options(), quiet_report())
        messages = []
        for frame in link.sent:
            self.assertEqual((frame.src, frame.dst, frame.ethertype),
                             (CLIENT, "ff:ff:ff:ff:ff:ff", 0x0800))
            ip = parse_ipv4(frame.payload)
            self.assertEqual((ip.src, ip.dst), ("0.0.0.0", "255.255.255.255"))
            udp = parse_udp(ip)
            self.assertEqual(udp[:2], (68, 67))
            self.assertIn(b"\x35\x01\x01", udp[2][240:])
            self.assertEqual(udp[2][28:34], bytes.fromhex("020000000001"))
            messages.append(udp[2])
        self.assertEqual(len(messages), 4)
        self.assertEqual(len({m[4:8] for m in messages}), 1)
        self.assertTrue(result["success"])
        self.assertEqual(result["sent"], 4)

    def test_discover_reply_broadcast_is_opt_in_without_changing_destination(self):
        for broadcast, flags in ((False, 0), (True, 0x8000)):
            with self.subTest(broadcast=broadcast):
                link = TimedLink()
                self.repeat.run_repeat(link, options(count=2, broadcast=broadcast), quiet_report())
                for frame in link.sent:
                    ip = parse_ipv4(frame.payload)
                    payload = parse_udp(ip)[2]
                    self.assertEqual(struct.unpack_from("!H", payload, 10)[0], flags)
                    self.assertEqual((frame.dst, ip.dst), ("ff:ff:ff:ff:ff:ff", "255.255.255.255"))

    def test_padi_never_advances_to_padr(self):
        def peer(link, frame):
            link.push(0x8863, b"\x11\x07\x00\x00\x00\x00")
        link = TimedLink(peer)
        result = self.repeat.run_repeat(link, options(protocol="pppoe", service="internet"), quiet_report())
        for frame in link.sent:
            self.assertEqual((frame.ethertype, frame.dst), (0x8863, "ff:ff:ff:ff:ff:ff"))
            self.assertEqual(frame.payload[:4], b"\x11\x09\x00\x00")
            self.assertIn(b"\x01\x01\x00\x08internet", frame.payload)
            self.assertIn(b"\x01\x03\x00\x08", frame.payload)
        self.assertEqual(len({f.payload for f in link.sent}), 1)
        self.assertEqual(result["sent"], 4)

    def test_no_reply_does_not_gate_100_or_150_ms_cadence(self):
        for interval, expected in ((100, [0, .1, .2, .3]), (150, [0, .15, .3, .45])):
            with self.subTest(interval=interval):
                link = TimedLink(send_cost=.02)
                result = self.repeat.run_repeat(link, options(interval_ms=interval), quiet_report())
                self.assertEqual(len(link.starts), 4)
                for actual, wanted in zip(link.starts, expected):
                    self.assertAlmostEqual(actual, wanted)
                self.assertAlmostEqual(result["actual_interval_avg_ms"], interval)
                self.assertAlmostEqual(result["actual_interval_min_ms"], interval)
                self.assertAlmostEqual(result["actual_interval_max_ms"], interval)

    def test_overrun_skips_slots_without_catchup_burst(self):
        link = TimedLink(send_cost=.25)
        result = self.repeat.run_repeat(link, options(), quiet_report())
        for actual, wanted in zip(link.starts, [0, .3, .6, .9]):
            self.assertAlmostEqual(actual, wanted)
        self.assertGreater(result["skipped_slots"], 0)

    def test_exact_boundary_overrun_uses_available_slot(self):
        link = TimedLink(send_cost=.2)
        result = self.repeat.run_repeat(link, options(count=6), quiet_report())
        for actual, expected in zip(link.starts, [0, .2, .4, .6, .8, 1.0]):
            self.assertAlmostEqual(actual, expected)
        self.assertEqual(result["skipped_slots"], 5)
        self.assertEqual(result["actual_interval_avg_ms"], 200)

    def test_interrupt_after_count_update_keeps_valid_partial_statistics(self):
        link, report = TimedLink(), quiet_report()
        previous_trace = sys.gettrace()
        def interrupt(frame, event, arg):
            result = frame.f_locals.get("result", {})
            if (event == "line" and frame.f_code is self.repeat.run_repeat.__code__
                    and result.get("sent") == 2):
                raise KeyboardInterrupt
            return interrupt
        try:
            sys.settrace(interrupt)
            with self.assertRaises(KeyboardInterrupt):
                self.repeat.run_repeat(link, options(), report)
        finally:
            sys.settrace(previous_trace)
        result = report.data["result"]
        self.assertEqual(result["sent"], 2)
        self.assertFalse(result["success"])
        for name in ("min", "avg", "max"):
            self.assertEqual(result[f"actual_interval_{name}_ms"], 100)
        json.dumps(result, allow_nan=False)

    def test_late_wakeup_rebases_next_send(self):
        class LateLink(TimedLink):
            def recv(self, timeout):
                frame = super().recv(timeout)
                if len(self.starts) == 1:
                    self.now += .25
                return frame
        link = LateLink()
        result = self.repeat.run_repeat(link, options(), quiet_report())
        for actual, wanted in zip(link.starts, [0, .35, .45, .55]):
            self.assertAlmostEqual(actual, wanted)
        self.assertGreaterEqual(result["max_lateness_ms"], 249)

    def test_receive_noise_is_drained_without_delaying_sends(self):
        def peer(link, frame):
            for i in range(1, 20):
                link.push(0x8863, b"noise", delay=i * .004)
        link = TimedLink(peer)
        self.repeat.run_repeat(link, options(count=3), quiet_report())
        for actual, wanted in zip(link.starts, [0, .1, .2]):
            self.assertAlmostEqual(actual, wanted)
        self.assertEqual(len(link.pending), 19)

    def test_unlimited_run_preserves_counts_on_interrupt(self):
        class InterruptLink(TimedLink):
            def recv(self, timeout):
                if len(self.sent) == 3:
                    raise KeyboardInterrupt
                return super().recv(timeout)
        link, report = InterruptLink(), quiet_report()
        with self.assertRaises(KeyboardInterrupt):
            self.repeat.run_repeat(link, options(count=0), report)
        self.assertEqual(report.data["result"]["sent"], 3)
        self.assertFalse(report.data["result"]["success"])
        self.assertIn("elapsed_seconds", report.data["result"])

    def test_failed_send_is_not_counted(self):
        class FailedLink(TimedLink):
            def send(self, kind, payload, dst):
                if len(self.sent) == 2:
                    raise ProbeError("send failed")
                super().send(kind, payload, dst)
        link, report = FailedLink(), quiet_report()
        with self.assertRaisesRegex(ProbeError, "send failed"):
            self.repeat.run_repeat(link, options(), report)
        self.assertEqual(report.data["result"]["sent"], 2)
        self.assertFalse(report.data["result"]["success"])

    def test_single_packet_has_no_interval_samples(self):
        result = self.repeat.run_repeat(TimedLink(), options(count=1), quiet_report())
        self.assertEqual(result["sent"], 1)
        self.assertIsNone(result["actual_interval_avg_ms"])

    def test_progress_events_do_not_grow_per_packet(self):
        report = quiet_report()
        self.repeat.run_repeat(TimedLink(), options(count=100), report)
        self.assertLess(len(report.data["events"]), 20)

    def test_ping_with_explicit_mac_sends_echo_without_arp_reply(self):
        link = TimedLink()
        result = self.repeat.run_repeat(link, options(protocol="ping", dst_mac=PEER), quiet_report())
        echoes = [f for f in link.sent if f.ethertype == 0x0800]
        self.assertEqual(len(echoes), 4)
        identifiers = set()
        for seq, frame in enumerate(echoes, 1):
            ip = parse_ipv4(frame.payload)
            self.assertEqual((frame.dst, ip.src, ip.dst, ip.protocol),
                             (PEER, "192.0.2.10", "192.0.2.1", 1))
            self.assertEqual(ip.payload[:2], b"\x08\x00")
            self.assertEqual(checksum(ip.payload), 0)
            self.assertEqual(len(ip.payload), 40)
            ident, actual_seq = struct.unpack("!HH", ip.payload[4:8])
            identifiers.add(ident)
            self.assertEqual(actual_seq, seq)
        self.assertEqual(len(identifiers), 1)
        self.assertTrue(result["success"])

    def test_ping_resolves_gateway_once_then_ignores_missing_echo(self):
        resolutions = []
        def peer(link, frame):
            if frame.ethertype == 0x0806 and frame.payload[14:18] != b"\0" * 4 and frame.payload[-4:] == bytes([192, 0, 2, 1]):
                resolutions.append(frame)
                link.push(0x0806, arp(2, PEER, "192.0.2.1", CLIENT, "192.0.2.10"))
        link = TimedLink(peer)
        result = self.repeat.run_repeat(link, options(protocol="ping", target="198.51.100.1", gateway="192.0.2.1"), quiet_report())
        self.assertEqual(len(resolutions), 1)
        echoes = [f for f in link.sent if f.ethertype == 0x0800]
        self.assertEqual(len(echoes), 4)
        self.assertEqual({f.dst for f in echoes}, {PEER})
        self.assertAlmostEqual(result["actual_interval_avg_ms"], 100)

    def test_ping_arp_failure_suggests_explicit_destination_mac(self):
        report = quiet_report()
        with self.assertRaisesRegex(ProbeTimeout, "dst-mac"):
            self.repeat.run_repeat(TimedLink(), options(protocol="ping"), report)
        self.assertEqual(report.data["result"]["sent"], 0)

    def test_explicit_mac_does_not_disable_address_conflict_check(self):
        def peer(link, frame):
            if frame.ethertype == 0x0806:
                link.push(0x0806, arp(2, PEER, "192.0.2.10", CLIENT, "192.0.2.10"))
        link = TimedLink(peer)
        with self.assertRaisesRegex(ProbeError, "conflict"):
            self.repeat.run_repeat(link, options(protocol="ping", dst_mac=PEER), quiet_report())
        self.assertFalse(any(f.ethertype == 0x0800 for f in link.sent))

    def test_ping_sequence_wraps_in_long_runs(self):
        link = TimedLink()
        result = self.repeat.run_repeat(link, options(protocol="ping", dst_mac=PEER, count=65537), quiet_report())
        last = parse_ipv4(link.sent[-1].payload)
        self.assertEqual(struct.unpack("!H", last.payload[6:8])[0], 1)
        self.assertEqual(result["sent"], 65537)

    def test_runtime_arp_is_answered_without_changing_echo_cadence(self):
        def peer(link, frame):
            if frame.ethertype == 0x0800:
                link.push(0x0806, arp(1, PEER, "192.0.2.1", "00:00:00:00:00:00", "192.0.2.10"))
        link = TimedLink(peer)
        result = self.repeat.run_repeat(link, options(protocol="ping", dst_mac=PEER), quiet_report())
        replies = [f for f in link.sent if f.ethertype == 0x0806 and f.payload[6:8] == b"\x00\x02"]
        self.assertEqual(len(replies), 3)
        self.assertEqual(result["sent"], 4)
        self.assertEqual(result["received_frames"], 3)
        self.assertAlmostEqual(result["actual_interval_avg_ms"], 100)

    def test_runtime_conflict_stops_with_partial_count(self):
        def peer(link, frame):
            if frame.ethertype == 0x0800:
                link.push(0x0806, arp(2, PEER, "192.0.2.10", CLIENT, "192.0.2.10"))
        report = quiet_report()
        with self.assertRaisesRegex(ProbeError, "conflict"):
            self.repeat.run_repeat(TimedLink(peer), options(protocol="ping", dst_mac=PEER), report)
        self.assertEqual(report.data["result"]["sent"], 1)
        self.assertFalse(report.data["result"]["success"])

    def test_ping_oversize_fails_before_any_arp_or_echo(self):
        link = TimedLink()
        link.mtu = 576
        with self.assertRaisesRegex(ValueError, "MTU|size"):
            self.repeat.run_repeat(link, options(protocol="ping", dst_mac=PEER, size=600), quiet_report())
        self.assertEqual(link.sent, [])


class BoundedReportTests(unittest.TestCase):
    def test_bounded_events_keep_recent_details_and_full_console_output(self):
        stream = io.StringIO()
        try:
            report = Report("repeat", stream, max_events=100)
        except TypeError as exc:
            self.fail(f"Repeat needs bounded report history: {exc}")
        for i in range(250):
            report.event("REPEAT", "INFO", "progress", sent=i)
        self.assertEqual(len(report.data["events"]), 100)
        self.assertEqual(report.data["events"][0]["sent"], 150)
        self.assertIn("sent=0", stream.getvalue())
        self.assertIn("sent=249", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
