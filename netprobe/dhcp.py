import secrets
import struct
from dataclasses import asdict, dataclass

from .ping import EthernetIPv4, echo
from .report import ProbeError, ProbeTimeout
from .wire import (BROADCAST, build_ipv4, build_udp, ip_bytes, ip_text,
                   mac_bytes, parse_ipv4, parse_udp, unicast_ip)

COOKIE = b"\x63\x82\x53\x63"
NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE"}


def parse_options(raw):
    options, pos = {}, 0
    while pos < len(raw):
        code = raw[pos]
        pos += 1
        if code == 255:
            return options
        if code == 0:
            continue
        if pos >= len(raw) or pos + 1 + raw[pos] > len(raw):
            raise ValueError("Truncated DHCP option")
        length = raw[pos]
        pos += 1
        options[code] = options.get(code, b"") + raw[pos:pos + length]
        pos += length
    return options


@dataclass
class Message:
    xid: int
    chaddr: bytes
    yiaddr: str
    options: dict


def parse_message(raw):
    if len(raw) < 240 or raw[236:240] != COOKIE or raw[:3] != b"\x02\x01\x06":
        return None
    try:
        opts = parse_options(raw[240:])
        overload = opts.get(52, b"\0")
        if len(overload) != 1 or overload[0] > 3:
            return None
        for flag, section in ((1, raw[108:236]), (2, raw[44:108])):
            if overload[0] & flag:
                for key, value in parse_options(section).items():
                    opts[key] = opts.get(key, b"") + value
        if len(opts.get(53, b"")) != 1 or len(opts.get(54, b"")) != 4:
            return None
        for key in (1, 51, 58, 59):
            if key in opts and len(opts[key]) != 4:
                return None
        if any(len(opts.get(key, b"")) % 4 for key in (3, 6)):
            return None
        return Message(struct.unpack_from("!I", raw, 4)[0], raw[28:34], ip_text(raw[16:20]), opts)
    except ValueError:
        return None


@dataclass
class Lease:
    ip: str
    server: str
    netmask: str
    gateway: str | None
    dns: list
    seconds: int
    t1: int
    t2: int


def lease_from(message, previous=None):
    opts = message.options
    address = message.yiaddr if message.yiaddr != "0.0.0.0" else (previous.ip if previous else "0.0.0.0")
    duration = struct.unpack("!I", opts[51])[0] if 51 in opts else (previous.seconds if previous else 0)
    if not duration:
        raise ProbeError("DHCP ACK has no valid lease time")
    netmask = ip_text(opts[1]) if 1 in opts else (previous.netmask if previous else "255.255.255.255")
    gateway = ip_text(opts[3][:4]) if opts.get(3) else (previous.gateway if previous else None)
    dns = [ip_text(opts[6][i:i + 4]) for i in range(0, len(opts.get(6, b"")), 4)]
    t1 = struct.unpack("!I", opts[58])[0] if 58 in opts else duration // 2
    t2 = struct.unpack("!I", opts[59])[0] if 59 in opts else duration * 7 // 8
    return Lease(unicast_ip(address), unicast_ip(ip_text(opts[54])), netmask, gateway, dns, duration, t1, t2)


class DhcpClient:
    def __init__(self, link, options, report):
        self.link, self.options, self.report = link, options, report
        self.xid = secrets.randbits(32)
        self.started = link.clock()
        self.client_id = b"\x01" + mac_bytes(link.mac)
        self.lease, self.channel = None, None
        self.expires, self.release_sent = 0, False

    def request(self, kind, server=None, requested=None, ciaddr="0.0.0.0", broadcast=True):
        data = bytearray(236)
        data[:4] = b"\x01\x01\x06\0"
        struct.pack_into("!IHH", data, 4, self.xid, min(65535, int(self.link.clock() - self.started)),
                         0x8000 if broadcast else 0)
        data[12:16], data[28:34] = ip_bytes(ciaddr), mac_bytes(self.link.mac)
        opts = [(53, bytes([kind])), (61, self.client_id)]
        if requested:
            opts.append((50, ip_bytes(requested)))
        if server:
            opts.append((54, ip_bytes(server)))
        if kind in (1, 3):
            opts += [(55, bytes([1, 3, 6, 51, 54, 58, 59])), (57, struct.pack("!H", min(1472, self.link.mtu - 28)))]
            if self.options.hostname:
                opts.append((12, self.options.hostname.encode("ascii")))
        data += COOKIE + b"".join(bytes([key, len(value)]) + value for key, value in opts) + b"\xff"
        return bytes(data).ljust(300, b"\0")

    def send(self, kind, payload, src="0.0.0.0", dst="255.255.255.255"):
        packet = build_ipv4(src, dst, 17, build_udp(src, dst, 68, 67, payload))
        if dst == "255.255.255.255":
            self.link.send(0x0800, packet, BROADCAST)
        else:
            self.channel.send_ip(packet)
        self.report.event("DHCP", "TX", NAMES[kind], source=src, destination=dst)

    def wait(self, expected, server=None):
        end = self.link.clock() + self.options.timeout
        while self.link.clock() < end:
            frame = self.link.recv(end - self.link.clock())
            if frame is None:
                break
            if self.channel:
                self.channel.handle_arp(frame)
            if frame.ethertype != 0x0800:
                continue
            ip = parse_ipv4(frame.payload)
            udp = parse_udp(ip) if ip else None
            if not udp or udp[:2] != (67, 68):
                continue
            msg = parse_message(udp[2])
            if not msg or msg.xid != self.xid or msg.chaddr != mac_bytes(self.link.mac):
                continue
            if 61 in msg.options and msg.options[61] != self.client_id:
                continue
            if server and msg.options[54] != ip_bytes(server):
                continue
            kind = msg.options[53][0]
            if kind not in expected:
                continue
            self.report.event("DHCP", "RX", NAMES[kind], server=ip_text(msg.options[54]))
            if kind == 6:
                self.lease = None
                raise ProbeError("DHCP NAK: address is no longer valid")
            return msg
        raise ProbeTimeout("DHCP response timeout")

    def exchange(self, expected, send, server=None):
        for attempt in range(self.options.retries + 1):
            if self.lease and self.link.clock() >= self.expires:
                self.lease = None
                raise ProbeError("DHCP lease expired during test")
            send()
            try:
                return self.wait(expected, server)
            except ProbeTimeout:
                self.report.event("DHCP", "RETRY", "Response timeout", attempt=attempt + 1)
        raise ProbeTimeout("DHCP response timeout after all attempts")

    def apply(self, msg):
        lease = lease_from(msg, self.lease)
        if self.lease and lease.ip != self.lease.ip:
            raise ProbeError("Renewal ACK changed ciaddr unexpectedly")
        self.lease = lease
        self.expires = self.link.clock() + lease.seconds
        self.channel = EthernetIPv4(self.link, lease.ip, lease.netmask, lease.gateway, self.report,
                                    self.options.timeout, self.options.retries)
        self.report.event("DHCP-LEASE", "INFO", "Lease accepted", **asdict(lease))

    def acquire(self):
        offer = self.exchange((2,), lambda: self.send(1, self.request(1)))
        server, requested = unicast_ip(ip_text(offer.options[54])), unicast_ip(offer.yiaddr)
        ack = self.exchange((5, 6), lambda: self.send(3, self.request(3, server, requested)), server)
        if ack.yiaddr != requested:
            raise ProbeError("DHCP ACK does not match requested address")
        self.apply(ack)
        try:
            self.channel.probe_address()
        except ProbeError as exc:
            if "conflict" in str(exc):
                self.send(4, self.request(4, server, requested))
                self.lease = None
            raise

    def renew(self):
        self.xid, self.started = secrets.randbits(32), self.link.clock()
        lease = self.lease
        self.report.event("DHCP-RENEW", "INFO", "Accelerated renewal test; not waiting for actual T1")
        try:
            ack = self.exchange((5, 6), lambda: self.send(3, self.request(3, ciaddr=lease.ip, broadcast=False),
                                                        lease.ip, lease.server), lease.server)
        except ProbeTimeout:
            self.report.event("DHCP-REBIND", "INFO", "Trying broadcast rebind before actual T2")
            ack = self.exchange((5, 6), lambda: self.send(3, self.request(3, ciaddr=lease.ip), lease.ip))
        self.apply(ack)

    def release(self):
        if not self.lease or self.link.clock() >= self.expires:
            return
        lease = self.lease
        try:
            self.send(7, self.request(7, server=lease.server, ciaddr=lease.ip, broadcast=False), lease.ip, lease.server)
            self.release_sent = True
            self.report.event("DHCP-RELEASE", "INFO", "Sent; DHCP RELEASE has no acknowledgement")
        except (ProbeError, OSError, ValueError) as exc:
            self.report.event("DHCP-RELEASE", "ERROR", "Release could not be sent", reason=str(exc))


def run_dhcp(link, options, report):
    client, result = DhcpClient(link, options, report), {}
    try:
        client.acquire()
        end = link.clock() + options.renew_delay
        if end >= client.expires:
            raise ValueError("renew-delay must be shorter than the acquired lease")
        while link.clock() < end:
            client.channel.recv_ip(end - link.clock())
        client.renew()
        result.update(lease=asdict(client.lease), success=True)
        if options.ping:
            stats = echo(client.channel, options.ping, options.count, options.interval,
                         options.timeout, options.size, report)
            result.update(ping=stats, success=stats["success"])
    finally:
        client.release()
    result["release_sent"] = client.release_sent
    result["success"] = result["success"] and client.release_sent
    return result
