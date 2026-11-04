import ipaddress
import secrets
import struct

from .report import ProbeError, ProbeTimeout
from .wire import (BROADCAST, ZERO_MAC, build_ipv4, checksum, ip_bytes, ip_text,
                   mac_bytes, mac_text, parse_ipv4, unicast_ip)


def arp_packet(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op,
                       mac_bytes(sha), ip_bytes(spa), mac_bytes(tha), ip_bytes(tpa))


def parse_arp(frame):
    if frame.ethertype != 0x0806 or len(frame.payload) < 28:
        return None
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = struct.unpack("!HHBBH6s4s6s4s", frame.payload[:28])
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4) or op not in (1, 2):
        return None
    if mac_text(sha) != frame.src or sha[0] & 1 or not any(sha):
        return None
    return op, mac_text(sha), ip_text(spa), mac_text(tha), ip_text(tpa)


class EthernetIPv4:
    def __init__(self, link, src_ip, netmask, gateway, report, timeout=2, retries=2):
        self.link, self.src_ip, self.report = link, unicast_ip(src_ip), report
        self.network = ipaddress.IPv4Network(f"{src_ip}/{netmask}", strict=False)
        self.gateway = unicast_ip(gateway) if gateway else None
        if self.network.prefixlen < 31 and ipaddress.IPv4Address(src_ip) in (self.network.network_address, self.network.broadcast_address):
            raise ValueError("Source IP is a subnet network/broadcast address")
        if self.gateway and ipaddress.IPv4Address(self.gateway) not in self.network:
            raise ValueError("Gateway must be on the source IP subnet")
        self.timeout, self.retries, self.mtu = timeout, retries, link.mtu
        self.clock, self.cache = link.clock, {}

    def next_hop(self, target):
        target = unicast_ip(target)
        if target == self.src_ip:
            raise ValueError("Target must not be the test source IP")
        address = ipaddress.IPv4Address(target)
        if address in self.network:
            if self.network.prefixlen < 31 and address in (self.network.broadcast_address, self.network.network_address):
                raise ValueError("Target must not be a subnet network/broadcast address")
            return target
        if not self.gateway:
            raise ValueError("A gateway is required for a target outside the source subnet")
        return self.gateway

    def handle_arp(self, frame, answer=True):
        arp = parse_arp(frame)
        if not arp:
            return None
        op, sha, spa, tha, tpa = arp
        if spa == self.src_ip and sha != self.link.mac:
            raise ProbeError(f"IPv4 address conflict: {self.src_ip} is used by {sha}")
        if answer and op == 1 and tpa == self.src_ip:
            self.link.send(0x0806, arp_packet(2, self.link.mac, self.src_ip, sha, spa), sha)
            self.report.event("ARP", "TX", "Reply for test address", ip=self.src_ip)
        return arp

    def probe_address(self):
        self.report.event("ARP-PROBE", "TX", "Checking test address", ip=self.src_ip)
        for _ in range(3):
            self.link.send(0x0806, arp_packet(1, self.link.mac, "0.0.0.0", ZERO_MAC, self.src_ip), BROADCAST)
            end = self.clock() + min(self.timeout, 1)
            while self.clock() < end:
                frame = self.link.recv(end - self.clock())
                if frame is None:
                    break
                arp = self.handle_arp(frame, answer=False)
                if arp and arp[0] == 1 and arp[2] == "0.0.0.0" and arp[4] == self.src_ip:
                    raise ProbeError(f"IPv4 address conflict: simultaneous ARP probe from {arp[1]}")
        self.link.send(0x0806, arp_packet(1, self.link.mac, self.src_ip, ZERO_MAC, self.src_ip), BROADCAST)

    def resolve(self, target):
        if target in self.cache:
            return self.cache[target]
        for attempt in range(self.retries + 1):
            self.report.event("ARP", "TX", "Who has", target=target, attempt=attempt + 1)
            self.link.send(0x0806, arp_packet(1, self.link.mac, self.src_ip, ZERO_MAC, target), BROADCAST)
            end = self.clock() + self.timeout
            while self.clock() < end:
                frame = self.link.recv(end - self.clock())
                if frame is None:
                    break
                arp = self.handle_arp(frame)
                if arp and arp[0] == 2 and arp[2] == target and arp[3] == self.link.mac and arp[4] == self.src_ip:
                    self.cache[target] = arp[1]
                    self.report.event("ARP", "RX", "Resolved", ip=target, mac=arp[1])
                    return arp[1]
        raise ProbeTimeout(f"ARP timeout for {target}")

    def prepare(self, target):
        self.resolve(self.next_hop(target))

    def send_ip(self, packet):
        ip = parse_ipv4(packet)
        self.link.send(0x0800, packet, self.resolve(self.next_hop(ip.dst)))

    def recv_ip(self, timeout):
        end = self.clock() + max(0, timeout)
        while self.clock() < end:
            frame = self.link.recv(end - self.clock())
            if frame is None:
                return None
            self.handle_arp(frame)
            if frame.ethertype == 0x0800:
                ip = parse_ipv4(frame.payload)
                if ip and ip.dst in (self.src_ip, "255.255.255.255"):
                    return frame.payload
        return None


def related_icmp_error(data, src, target, ident, seq):
    if len(data) < 36 or data[0] not in (3, 11, 12):
        return False
    quoted = data[8:]
    ihl = (quoted[0] & 15) * 4
    return (quoted[0] >> 4 == 4 and ihl >= 20 and len(quoted) >= ihl + 8
            and quoted[9] == 1 and quoted[12:16] == ip_bytes(src)
            and quoted[16:20] == ip_bytes(target) and quoted[ihl] == 8
            and quoted[ihl + 4:ihl + 8] == struct.pack("!HH", ident, seq))


def echo(channel, target, count, interval, timeout, size, report):
    unicast_ip(target)
    if not 1 <= count <= 65535 or not 8 <= size <= channel.mtu - 28:
        raise ValueError(f"count must be 1..65535; size must be 8..{channel.mtu - 28}")
    channel.prepare(target)
    ident = secrets.randbelow(65536)
    token = secrets.token_bytes(size)
    samples, errors = [], 0
    for seq in range(1, count + 1):
        payload = struct.pack("!I", seq) + token[4:]
        request = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
        request = request[:2] + struct.pack("!H", checksum(request)) + request[4:]
        sent = channel.clock()
        channel.send_ip(build_ipv4(channel.src_ip, target, 1, request, seq))
        report.event("PING", "TX", "Echo Request", target=target, seq=seq, bytes=size)
        end, matched = sent + timeout, False
        while channel.clock() < end:
            raw = channel.recv_ip(end - channel.clock())
            if raw is None:
                break
            ip = parse_ipv4(raw)
            if not ip or ip.dst != channel.src_ip or ip.protocol != 1:
                continue
            data = ip.payload
            if len(data) < 8 or checksum(data):
                continue
            if (ip.src == target and data[:2] == b"\0\0" and data[4:8] == struct.pack("!HH", ident, seq)
                    and data[8:] == payload):
                rtt = (channel.clock() - sent) * 1000
                samples.append(rtt)
                report.event("PING", "RX", "Echo Reply", seq=seq, ttl=ip.ttl, rtt_ms=round(rtt, 3))
                matched = True
                break
            if related_icmp_error(data, channel.src_ip, target, ident, seq):
                errors += 1
                report.event("PING", "ERROR", "ICMP error", seq=seq, source=ip.src, type=data[0], code=data[1])
                matched = True
                break
        if not matched:
            report.event("PING", "TIMEOUT", "No matching Echo Reply", seq=seq)
        wait_end = sent + interval if seq < count else channel.clock()
        while channel.clock() < wait_end:
            channel.recv_ip(wait_end - channel.clock())
    result = {"target": target, "sent": count, "received": len(samples), "icmp_errors": errors,
              "loss_percent": round(100 * (count - len(samples)) / count, 2),
              "rtt_min_ms": round(min(samples), 3) if samples else None,
              "rtt_avg_ms": round(sum(samples) / len(samples), 3) if samples else None,
              "rtt_max_ms": round(max(samples), 3) if samples else None,
              "success": len(samples) == count}
    report.event("PING", "INFO", "Statistics", **result)
    return result


def run_ping(link, src_ip, target, netmask, gateway, count, interval, timeout, size, report, retries=2):
    channel = EthernetIPv4(link, src_ip, netmask, gateway, report, timeout, retries)
    channel.next_hop(target)
    channel.probe_address()
    return echo(channel, target, count, interval, timeout, size, report)
