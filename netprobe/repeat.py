import math
import secrets
import struct

from .dhcp import DhcpClient
from .ping import EthernetIPv4
from .pppoe import envelope, tag
from .report import ProbeTimeout
from .wire import BROADCAST, build_ipv4, build_udp, checksum


def packet_sender(link, options, report):
    if options.protocol == "ping":
        if not 8 <= options.size <= link.mtu - 28:
            raise ValueError(f"ICMP size must be 8..{link.mtu - 28} for the interface MTU")
        channel = EthernetIPv4(link, options.src_ip, options.netmask, options.gateway,
                               report, options.timeout, options.retries)
        next_hop = channel.next_hop(options.target)
        channel.probe_address()
        if options.dst_mac:
            destination = options.dst_mac
        else:
            try:
                destination = channel.resolve(next_hop)
            except ProbeTimeout as exc:
                raise ProbeTimeout(f"{exc}; specify --dst-mac with the known next-hop MAC to send without ARP resolution") from None
        ident, token = secrets.randbelow(65536), secrets.token_bytes(options.size - 4)

        def send_packet(number):
            seq = number & 0xffff
            data = struct.pack("!I", number & 0xffffffff) + token
            request = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + data
            request = request[:2] + struct.pack("!H", checksum(request)) + request[4:]
            packet = build_ipv4(options.src_ip, options.target, 1, request, seq)
            link.send(0x0800, packet, destination)

        return send_packet, channel
    if options.protocol == "dhcp":
        client = DhcpClient(link, options, report)
        payload = client.request(1)
        src, dst = "0.0.0.0", "255.255.255.255"
        payload = build_ipv4(src, dst, 17, build_udp(src, dst, 68, 67, payload))
        kind = 0x0800
    else:
        tags = tag(0x0101, options.service.encode("utf-8")) + tag(0x0103, secrets.token_bytes(8))
        payload, kind = envelope(9, 0, tags), 0x8863

    def send_packet(number):
        link.send(kind, payload, BROADCAST)

    return send_packet, None


def run_repeat(link, options, report):
    interval = options.interval_ms / 1000
    started = link.clock()
    result = {"protocol": options.protocol, "interval_ms": options.interval_ms,
              "requested_count": options.count, "sent": 0, "received_frames": 0,
              "success": False, "skipped_slots": 0, "max_lateness_ms": 0,
              "actual_interval_min_ms": None, "actual_interval_avg_ms": None,
              "actual_interval_max_ms": None}
    report.data["result"] = result
    timing = (0, None, None, None, None)
    try:
        report.event("REPEAT", "INFO", "Send-only mode; responses do not gate sends or prove connectivity",
                     protocol=options.protocol, interval_ms=options.interval_ms,
                     count=options.count, test_mac=link.mac)
        send_packet, channel = packet_sender(link, options, report)
        due = link.clock()
        progress_due = due + 1
        while not options.count or result["sent"] < options.count:
            while True:
                remaining = due - link.clock()
                if remaining <= 0:
                    break
                frame = link.recv(remaining)
                if frame is not None:
                    result["received_frames"] += 1
                    if channel:
                        channel.handle_arp(frame)
            sent_at = link.clock()
            lateness = max(0, sent_at - due)
            send_packet(result["sent"] + 1)
            sent, first, previous, minimum, maximum = timing
            if not sent:
                updated = (1, sent_at, sent_at, None, None)
            else:
                spacing = sent_at - previous
                updated = (sent + 1, first, sent_at,
                           spacing if minimum is None else min(minimum, spacing),
                           spacing if maximum is None else max(maximum, spacing))
            # One assignment keeps the count and interval samples coherent on Ctrl+C.
            timing = updated
            result["sent"] = timing[0]
            result["max_lateness_ms"] = max(result["max_lateness_ms"], lateness * 1000)
            result["skipped_slots"] += int(lateness / interval)
            if options.count and result["sent"] >= options.count:
                break
            now = link.clock()
            if now >= progress_due:
                report.event("REPEAT", "INFO", "Sending", sent=result["sent"],
                             received_frames=result["received_frames"],
                             capture_dropped=link.dropped)
                progress_due = link.clock() + 1
            due = sent_at + interval
            now = link.clock()
            if due < now:
                # Float roundoff must not turn an exact boundary into a missed slot.
                tolerance = 2 * max(math.ulp(now), math.ulp(due))
                skipped = max(0, math.ceil((now - due - tolerance) / interval))
                result["skipped_slots"] += skipped
                due += skipped * interval
        result["success"] = True
        return result
    finally:
        sent, first, previous, minimum, maximum = timing
        result["sent"] = sent
        result["elapsed_seconds"] = round(link.clock() - started, 6)
        result["capture_dropped"] = link.dropped
        result["max_lateness_ms"] = round(result["max_lateness_ms"], 6)
        if sent > 1:
            result["actual_interval_min_ms"] = round(minimum * 1000, 6)
            result["actual_interval_avg_ms"] = round((previous - first) * 1000 / (sent - 1), 6)
            result["actual_interval_max_ms"] = round(maximum * 1000, 6)
        report.event("REPEAT", "INFO", "Software send statistics; not a connectivity result", **result)
