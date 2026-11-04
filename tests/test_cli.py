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
            data = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertTrue(link.closed)
        self.assertTrue(ac.padt)
        self.assertNotIn("secret", json.dumps(data))

    def test_capture_failure_writes_failure_json(self):
        adapter = Interface(9, "Ethernet", "test", "{AAA}", "00:11:22:33:44:55", "Up", 1500)
        with tempfile.TemporaryDirectory() as d:
            output = str(Path(d) / "result.json")
            with patch.object(self.cli, "list_interfaces", return_value=[adapter]), patch.object(self.cli, "Link", side_effect=PermissionError("access denied")), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = self.cli.main(["dhcp", "--iface", "9", "--json", output])
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
