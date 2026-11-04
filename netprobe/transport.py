import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass

from .report import ProbeError
from .wire import accept_frame, decode_frame, encode_frame, validate_mac


@dataclass(frozen=True)
class Interface:
    index: int
    name: str
    description: str
    guid: str
    mac: str
    status: str
    mtu: int
    media: str = "802.3"


def select_interface(interfaces, selector):
    key = selector.casefold().removeprefix("\\device\\npf_")
    matches = [i for i in interfaces if str(i.index) == key or i.name.casefold() == key
               or i.guid.casefold() == key]
    if len(matches) != 1:
        raise ValueError("Interface not found or ambiguous; use interfaces and its exact index/name/GUID")
    return matches[0]


def list_interfaces():
    if os.name != "nt":
        raise ProbeError("Live capture is supported on Windows only")
    script = """
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$ErrorActionPreference = 'Stop'
$ips = @(Get-NetIPInterface -AddressFamily IPv4)
@(Get-NetAdapter | ForEach-Object {
    $a = $_
    $ip = $ips | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | Select-Object -First 1
    [pscustomobject]@{index=$a.ifIndex; name=$a.Name; description=$a.InterfaceDescription;
        guid=$a.InterfaceGuid.ToString(); mac=$a.MacAddress; status=$a.Status.ToString();
        mtu=$(if ($ip) {$ip.NlMtu} else {1500}); media=$a.MediaType.ToString()}
}) | ConvertTo-Json -Compress
"""
    completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                               capture_output=True, encoding="utf-8", errors="replace", timeout=30)
    if completed.returncode:
        raise ProbeError("Cannot enumerate Windows adapters: " + completed.stderr.strip())
    data = json.loads(completed.stdout or "[]")
    if isinstance(data, dict):
        data = [data]
    return [Interface(int(i["index"]), i["name"], i["description"],
                      "{" + i["guid"].strip("{}") + "}", (i["mac"] or "").replace("-", ":").lower(),
                      i["status"], int(i["mtu"]), i["media"]) for i in data]


class Link:
    def __init__(self, interface, mac, vlan=None, pcp=0, pcap=None):
        self.mac, self.vlan, self.pcp = validate_mac(mac), vlan, pcp
        encode_frame(self.mac, self.mac, 0x0800, b"", vlan, pcp)
        self.mtu = min(interface.mtu, 1500)
        self.clock = time.monotonic
        self.frames = queue.Queue(maxsize=4096)
        self.dropped = 0
        self.socket = self.sniffer = self.writer = None
        self.capture_error = None
        self.lock = threading.Lock()
        try:
            from scapy.all import AsyncSniffer, Ether, PcapWriter, conf
            self.ether = Ether
            if not conf.use_pcap:
                conf.use_pcap = True
            if not conf.use_pcap:
                raise ProbeError("Npcap is not available; install Npcap and run as Administrator")
            candidates = [i for i in conf.ifaces.values()
                          if interface.guid.casefold() in i.network_name.casefold()]
            if len(candidates) != 1:
                raise ProbeError("Adapter has no unique Npcap mapping; restart after installing Npcap")
            self.socket = conf.L2socket(iface=candidates[0], promisc=True)
            if pcap:
                self.writer = PcapWriter(str(pcap), linktype=1, sync=True)
            ready = threading.Event()
            self.sniffer = AsyncSniffer(opened_socket=self.socket, store=False,
                                        prn=self._capture, started_callback=ready.set)
            self.sniffer.start()
            if not ready.wait(5):
                raise ProbeError("Npcap capture did not become ready")
        except BaseException:
            self.close()
            raise

    def _capture(self, packet):
        try:
            raw = bytes(packet)
            frame = decode_frame(raw)
            if not accept_frame(frame, self.mac, self.vlan):
                return
            if self.writer:
                with self.lock:
                    self.writer.write(raw)
            try:
                self.frames.put_nowait(frame)
            except queue.Full:
                self.dropped += 1
        except Exception as exc:
            self.capture_error = exc

    def send(self, ethertype, payload, dst):
        if self.capture_error:
            raise ProbeError("Capture failed: " + str(self.capture_error))
        if len(payload) > self.mtu:
            raise ProbeError(f"Payload exceeds interface MTU {self.mtu}")
        raw = encode_frame(self.mac, dst, ethertype, payload, self.vlan, self.pcp)
        if self.writer:
            with self.lock:
                self.writer.write(raw)
        sent = self.socket.send(self.ether(raw))
        if sent is not None and sent < 0:
            raise ProbeError("Npcap send failed; check adapter permissions and driver support")

    def recv(self, timeout):
        deadline = self.clock() + max(0, timeout)
        while True:
            if self.capture_error:
                raise ProbeError("Capture failed: " + str(self.capture_error))
            if self.sniffer and not self.sniffer.running:
                raise ProbeError("Npcap capture stopped unexpectedly")
            remaining = deadline - self.clock()
            if remaining <= 0:
                return None
            try:
                return self.frames.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                pass

    def close(self):
        try:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()
        finally:
            try:
                if self.socket:
                    self.socket.close()
            finally:
                if self.writer:
                    self.writer.close()
                self.socket = self.writer = self.sniffer = None
