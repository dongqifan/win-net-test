import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_core import required
from helpers import FakeLink, quiet_report
from test_pppoe import AccessConcentrator
from netprobe.transport import Interface

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def setUp(self):
        self.cli = required("netprobe.cli")

    def test_help_works_without_npcap_access(self):
        for command in ([], ["dhcp"], ["pppoe"], ["ping"], ["interfaces"]):
            result = subprocess.run([sys.executable, str(ROOT / "nettest.py"), *command, "--help"],
                                    capture_output=True, encoding="utf-8", errors="replace")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage", result.stdout)

    def test_invalid_parameters_fail_before_network_access(self):
        for args in (["dhcp", "--iface", "9", "--vlan", "4095"],
                     ["dhcp", "--iface", "9", "--pcp", "3"],
                     ["dhcp", "--iface", "9", "--timeout", "nan"],
                     ["dhcp", "--iface", "9", "--timeout", "inf"],
                     ["dhcp", "--iface", "9", "--retries", "-1"],
                     ["dhcp", "--iface", "9", "--mac", "ff:ff:ff:ff:ff:ff"],
                     ["pppoe", "--iface", "9", "--username", "x", "--count", "0"],
                     ["ping", "--iface", "9", "--src-ip", "192.0.2.10", "--netmask", "255.255.255.0", "--target", "example.org"],
                     ["ping", "--iface", "9", "--src-ip", "192.0.2.10", "--netmask", "255.255.255.0", "--target", "198.51.100.1"]):
            with self.subTest(args=args), patch.object(self.cli, "list_interfaces", side_effect=AssertionError("must not access network")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(self.cli.main(args), 2)

    def test_pppoe_cli_report_and_cleanup(self):
        ac, link = AccessConcentrator(), FakeLink()
        link.peer = ac
        link.close = lambda: setattr(link, "closed", True)
        adapter = Interface(9, "以太网", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        with tempfile.TemporaryDirectory() as d:
            output = str(Path(d) / "result.json")
            with patch.object(self.cli, "list_interfaces", return_value=[adapter]), patch.object(self.cli, "Link", return_value=link), \
                    patch.dict(os.environ, {"NETTEST_PPPOE_PASSWORD": "secret"}), contextlib.redirect_stdout(io.StringIO()):
                rc = self.cli.main(["pppoe", "--iface", "9", "--username", "tester", "--ping", "198.51.100.1", "--json", output])
            self.assertTrue(Path(output).is_file(), "Command must save a JSON result")
            data = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertTrue(link.closed)
        self.assertTrue(ac.padt)
        self.assertNotIn("secret", json.dumps(data))

    def test_repeat_help_and_dispatch_without_protocol_access(self):
        for command in (["repeat", "--help"],):
            result = subprocess.run([sys.executable, str(ROOT / "nettest.py"), *command],
                                    capture_output=True, encoding="utf-8", errors="replace")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--interval-ms", result.stdout)

    def test_dhcp_broadcast_option_controls_wire_flag_in_both_commands(self):
        import struct
        from test_dhcp import Server
        from netprobe.wire import parse_ipv4, parse_udp
        adapter = Interface(9, "Ethernet", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        for command in (["dhcp"], ["repeat", "--protocol", "dhcp", "--count", "1"]):
            for extra, flags in (([], 0), (["--broadcast"], 0x8000)):
                with self.subTest(command=command, extra=extra):
                    link = FakeLink(Server() if command == ["dhcp"] else None)
                    link.close = lambda: None
                    with (patch.object(self.cli, "list_interfaces", return_value=[adapter]),
                          patch.object(self.cli, "Link", return_value=link),
                          contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
                        rc = self.cli.main(command + ["--iface", "9"] + extra)
                    self.assertEqual(rc, 0)
                    first = link.sent[0]
                    ip = parse_ipv4(first.payload)
                    data = parse_udp(ip)[2]
                    self.assertEqual(struct.unpack_from("!H", data, 10)[0], flags)
                    self.assertEqual((first.dst, ip.dst), ("ff:ff:ff:ff:ff:ff", "255.255.255.255"))

    def test_repeat_invalid_arguments_fail_before_network_access(self):
        base = ["repeat", "--iface", "9"]
        dhcp = base + ["--protocol", "dhcp"]
        ping = base + ["--protocol", "ping", "--src-ip", "192.0.2.10", "--netmask", "24", "--target", "192.0.2.1"]
        cases = (
            dhcp + ["--interval-ms", "99"], dhcp + ["--interval-ms", "60001"],
            dhcp + ["--interval-ms", "nan"], dhcp + ["--interval-ms", "100.5"],
            dhcp + ["--count", "-1"], dhcp + ["--count", "2147483648"],
            dhcp + ["--pcp", "3"], dhcp + ["--hostname", "bad name"],
            dhcp + ["--service", "internet"], dhcp + ["--target", "192.0.2.1"],
            base + ["--protocol", "pppoe", "--service", "x" * 256],
            base + ["--protocol", "ping", "--target", "192.0.2.1"],
            ping + ["--size", "1473"], ping + ["--dst-mac", "ff:ff:ff:ff:ff:ff"],
            ping + ["--target", "198.51.100.1"], ping + ["--target", "192.0.2.10"],
            ping + ["--gateway", "198.51.100.1"], ping + ["--hostname", "unused"],
            ping + ["--broadcast"], base + ["--protocol", "pppoe", "--broadcast"],
        )
        for args in cases:
            with self.subTest(args=args), patch.object(self.cli, "list_interfaces", side_effect=AssertionError("must not access network")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(self.cli.main(args), 2)

    def test_repeat_dispatches_and_closes_link(self):
        link = FakeLink()
        link.close = lambda: setattr(link, "closed", True)
        def open_link(interface, mac, vlan, pcp, pcap, precise_timing=False):
            self.assertTrue(precise_timing, "Repeat must select precise transport waits")
            return link
        adapter = Interface(9, "以太网", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        with (patch.object(self.cli, "list_interfaces", return_value=[adapter]),
              patch.object(self.cli, "Link", side_effect=open_link),
              contextlib.redirect_stdout(io.StringIO())):
            rc = self.cli.main(["repeat", "--protocol", "dhcp", "--iface", "9", "--interval-ms", "100", "--count", "2"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(link.sent), 2)
        self.assertTrue(link.closed)

    def test_repeat_interruption_saves_partial_json_and_closes(self):
        class InterruptLink(FakeLink):
            def recv(self, timeout):
                if len(self.sent) >= 3:
                    raise KeyboardInterrupt
                return super().recv(timeout)
        link = InterruptLink()
        link.close = lambda: setattr(link, "closed", True)
        adapter = Interface(9, "Ethernet", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        with tempfile.TemporaryDirectory() as d:
            output = str(Path(d) / "repeat.json")
            with (patch.object(self.cli, "list_interfaces", return_value=[adapter]),
                  patch.object(self.cli, "Link", return_value=link),
                  contextlib.redirect_stdout(io.StringIO())):
                rc = self.cli.main(["repeat", "--protocol", "pppoe", "--iface", "9",
                                    "--interval-ms", "100", "--json", output])
            self.assertTrue(Path(output).is_file(), "Command must save a JSON result")
            data = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertEqual(rc, 130)
        self.assertEqual(data["result"]["sent"], 3)
        self.assertFalse(data["success"])
        self.assertTrue(link.closed)

    def test_repeat_send_error_keeps_count_in_failure_json(self):
        from netprobe.report import ProbeError
        class FailedLink(FakeLink):
            def send(self, kind, payload, dst):
                if len(self.sent) == 1:
                    raise ProbeError("send failed")
                super().send(kind, payload, dst)
        link = FailedLink()
        link.close = lambda: setattr(link, "closed", True)
        adapter = Interface(9, "Ethernet", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        with tempfile.TemporaryDirectory() as d:
            output = str(Path(d) / "repeat.json")
            with (patch.object(self.cli, "list_interfaces", return_value=[adapter]),
                  patch.object(self.cli, "Link", return_value=link),
                  contextlib.redirect_stdout(io.StringIO())):
                rc = self.cli.main(["repeat", "--protocol", "dhcp", "--iface", "9",
                                    "--interval-ms", "150", "--count", "3", "--json", output])
            self.assertTrue(Path(output).is_file(), "Command must save a JSON result")
            data = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertEqual(rc, 1)
        self.assertEqual(data["result"]["sent"], 1)
        self.assertFalse(data["success"])
        self.assertTrue(link.closed)

    def test_repeat_long_run_json_keeps_bounded_history(self):
        link = FakeLink()
        link.close = lambda: setattr(link, "closed", True)
        adapter = Interface(9, "Ethernet", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        with tempfile.TemporaryDirectory() as d:
            output = str(Path(d) / "repeat.json")
            with (patch.object(self.cli, "list_interfaces", return_value=[adapter]),
                  patch.object(self.cli, "Link", return_value=link),
                  contextlib.redirect_stdout(io.StringIO())):
                rc = self.cli.main(["repeat", "--protocol", "pppoe", "--iface", "9",
                                    "--interval-ms", "100", "--count", "2000", "--json", output])
            self.assertTrue(Path(output).is_file(), "Command must save a JSON result")
            data = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertEqual(data["result"]["sent"], 2000)
        self.assertLessEqual(len(data["events"]), 100)
        self.assertTrue(link.closed)

    def test_capture_failure_writes_failure_json(self):
        adapter = Interface(9, "Ethernet", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        with tempfile.TemporaryDirectory() as d:
            output = str(Path(d) / "result.json")
            with patch.object(self.cli, "list_interfaces", return_value=[adapter]), patch.object(self.cli, "Link", side_effect=PermissionError("access denied")), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = self.cli.main(["dhcp", "--iface", "9", "--json", output])
            self.assertTrue(Path(output).is_file(), "Command must save a JSON result")
            data = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertEqual(rc, 2)
        self.assertFalse(data["success"])

    def test_existing_output_files_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "report.json"
            output.write_text("keep", encoding="utf-8")
            with patch.object(self.cli, "list_interfaces", side_effect=AssertionError("must not access network")), contextlib.redirect_stderr(io.StringIO()):
                rc = self.cli.main(["dhcp", "--iface", "9", "--json", str(output)])
            self.assertEqual(rc, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
