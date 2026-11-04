import ipaddress
import secrets
import struct
from dataclasses import dataclass

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


def mac_bytes(value):
    parts = value.replace("-", ":").split(":")
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        raise ValueError("MAC must contain six hexadecimal octets")
    return bytes(int(p, 16) for p in parts)


def mac_text(value):
    return ":".join(f"{v:02x}" for v in value)


def validate_mac(value):
    raw = mac_bytes(value)
    if raw[0] & 1 or not any(raw):
        raise ValueError("Source MAC must be a nonzero unicast MAC")
    return mac_text(raw)


def random_mac():
    raw = bytearray(secrets.token_bytes(6))
    raw[0] = (raw[0] | 2) & 0xfe
    return mac_text(raw)


@dataclass(frozen=True)
class Frame:
    src: str
    dst: str
    ethertype: int
    payload: bytes
    vlan: int | None = None
    pcp: int = 0


def encode_frame(src, dst, ethertype, payload, vlan=None, pcp=0):
    validate_mac(src)
    if not 0 <= pcp <= 7 or (vlan is None and pcp):
        raise ValueError("PCP requires a VLAN and must be 0..7")
    if vlan is not None and not 1 <= vlan <= 4094:
        raise ValueError("VLAN must be 1..4094")
    header = mac_bytes(dst) + mac_bytes(src)
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, pcp << 13 | vlan)
    return header + struct.pack("!H", ethertype) + payload


def decode_frame(raw):
    if len(raw) < 14:
        return None
    dst, src = mac_text(raw[:6]), mac_text(raw[6:12])
    kind = struct.unpack_from("!H", raw, 12)[0]
    vlan, pcp, offset = None, 0, 14
    if kind == 0x8100:
        if len(raw) < 18:
            return None
        tci, kind = struct.unpack_from("!HH", raw, 14)
        vlan, pcp, offset = tci & 0xfff, tci >> 13, 18
    if kind in (0x8100, 0x88a8, 0x9100):
        return None
    return Frame(src, dst, kind, raw[offset:], vlan, pcp)


def accept_frame(frame, mac, vlan):
    return (frame is not None and frame.vlan == vlan and frame.src != mac
            and frame.dst in (mac, BROADCAST))


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ip_bytes(value):
    return ipaddress.IPv4Address(value).packed


def ip_text(value):
    return str(ipaddress.IPv4Address(value))


def unicast_ip(value):
    ip = ipaddress.IPv4Address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or int(ip) == 0xffffffff:
        raise ValueError("Expected a unicast IPv4 address")
    return str(ip)


def build_ipv4(src, dst, protocol, payload, ident=0, ttl=64):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                         0x4000, ttl, protocol, 0, ip_bytes(src), ip_bytes(dst))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


@dataclass(frozen=True)
class IPv4:
    src: str
    dst: str
    protocol: int
    payload: bytes
    ttl: int


def parse_ipv4(raw):
    if len(raw) < 20 or raw[0] >> 4 != 4:
        return None
    ihl, length = (raw[0] & 15) * 4, struct.unpack_from("!H", raw, 2)[0]
    if ihl < 20 or length < ihl or length > len(raw) or checksum(raw[:ihl]):
        return None
    if struct.unpack_from("!H", raw, 6)[0] & 0x3fff:
        return None
    return IPv4(ip_text(raw[12:16]), ip_text(raw[16:20]), raw[9], raw[ihl:length], raw[8])


def build_udp(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, 17, length)
    check = checksum(pseudo + header + payload) or 0xffff
    return header[:6] + struct.pack("!H", check) + payload


def parse_udp(ip):
    data = ip.payload
    if ip.protocol != 17 or len(data) < 8:
        return None
    sport, dport, length, check = struct.unpack_from("!HHHH", data)
    if length < 8 or length > len(data):
        return None
    pseudo = ip_bytes(ip.src) + ip_bytes(ip.dst) + struct.pack("!BBH", 0, 17, length)
    if check and checksum(pseudo + data[:length]):
        return None
    return sport, dport, data[8:length]
