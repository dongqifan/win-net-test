import os
import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from netprobe.report import ProbeError
from netprobe.transport import Link, list_interfaces
from netprobe.wire import encode_frame
from helpers import CLIENT, PEER


class TransportTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows read-only integration")
    def test_windows_adapter_mtu_is_numeric(self):
        adapters = list_interfaces()
        self.assertTrue(adapters)
        self.assertTrue(all(isinstance(i.mtu, int) and i.mtu > 0 for i in adapters))
        self.assertTrue(all(i.guid.startswith("{") for i in adapters))

    def make_link(self):
        link = Link.__new__(Link)
        link.mac, link.vlan, link.pcp, link.mtu = CLIENT, 100, 3, 1500
        link.capture_error, link.writer = None, None
        link.clock, link.lock = time.monotonic, threading.Lock()
        link.frames, link.dropped = queue.Queue(maxsize=1), 0
        link.socket = SimpleNamespace(send=lambda packet: -1)
        link.ether = bytes
        return link

    def test_npcap_negative_send_result_is_error(self):
        link = self.make_link()
        with self.assertRaisesRegex(ProbeError, "send"):
            link.send(0x0800, b"test", PEER)

    def test_capture_filters_vlan_and_reports_overflow(self):
        link = self.make_link()
        link._capture(encode_frame(PEER, CLIENT, 0x0806, b"arp", 101))
        self.assertTrue(link.frames.empty())
        link._capture(encode_frame(PEER, CLIENT, 0x0806, b"arp", 100))
        link._capture(encode_frame(PEER, CLIENT, 0x0806, b"arp", 100))
        self.assertEqual(link.dropped, 1)
        self.assertEqual(link.frames.get().vlan, 100)

    def test_capture_keeps_vlan_pcp_in_pcap(self):
        from scapy.utils import PcapWriter, RawPcapReader
        link = self.make_link()
        raw = encode_frame(PEER, CLIENT, 0x0806, b"arp", 100, 5)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "test.pcap"
            link.writer = PcapWriter(str(path), linktype=1, sync=True)
            link._capture(raw)
            link.writer.close()
            with RawPcapReader(str(path)) as reader:
                records = list(reader)
            self.assertEqual(records[0][0], raw)


if __name__ == "__main__":
    unittest.main()
