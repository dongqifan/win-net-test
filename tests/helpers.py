import heapq
import io
import struct

from netprobe.report import Report
from netprobe.wire import Frame, ip_bytes, mac_bytes

CLIENT = "02:00:00:00:00:01"
PEER = "02:00:00:00:00:02"


class FakeLink:
    def __init__(self, peer=None):
        self.mac, self.mtu, self.vlan = CLIENT, 1500, None
        self.now, self.counter, self.dropped = 0.0, 0, 0
        self.sent, self.pending = [], []
        self.peer = peer

    def clock(self):
        return self.now

    def send(self, kind, payload, dst):
        frame = Frame(self.mac, dst, kind, payload)
        self.sent.append(frame)
        if self.peer:
            self.peer(self, frame)

    def push(self, kind, payload, src=PEER, dst=CLIENT, delay=0.01):
        self.counter += 1
        heapq.heappush(self.pending, (self.now + delay, self.counter, Frame(src, dst, kind, payload)))

    def recv(self, timeout):
        end = self.now + max(0, timeout)
        if self.pending and self.pending[0][0] <= end:
            when, _, frame = heapq.heappop(self.pending)
            self.now = max(self.now, when)
            return frame
        self.now = end
        return None


def quiet_report(command="test"):
    return Report(command, stream=io.StringIO())


def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op,
                       mac_bytes(sha), ip_bytes(spa), mac_bytes(tha), ip_bytes(tpa))
