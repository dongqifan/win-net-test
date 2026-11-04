import hashlib
import secrets
import struct
from collections import deque

from .ping import echo
from .report import ProbeError, ProbeTimeout
from .wire import BROADCAST, ip_bytes, ip_text, unicast_ip

LCP, IPCP, PAP, CHAP, IPV4 = 0xc021, 0x8021, 0xc023, 0xc223, 0x0021
LABELS = {LCP: "LCP", IPCP: "IPCP", PAP: "PAP", CHAP: "CHAP", IPV4: "PPP-IP"}


def envelope(code, sid, data):
    return struct.pack("!BBHH", 0x11, code, sid, len(data)) + data


def parse_envelope(raw):
    if len(raw) < 6 or raw[0] != 0x11:
        return None
    _, code, sid, length = struct.unpack_from("!BBHH", raw)
    if 6 + length > len(raw):
        return None
    return code, sid, raw[6:6 + length]


def tag(kind, value):
    return struct.pack("!HH", kind, len(value)) + value


def parse_tags(raw):
    result = {}
    while raw:
        if len(raw) < 4:
            raise ValueError("Truncated PPPoE tag")
        kind, size = struct.unpack_from("!HH", raw)
        if len(raw) < 4 + size:
            raise ValueError("Truncated PPPoE tag value")
        if kind == 0:
            if size:
                raise ValueError("Invalid end tag")
            break
        result.setdefault(kind, []).append(raw[4:4 + size])
        raw = raw[4 + size:]
    return result


def control(code, ident, data=b""):
    return struct.pack("!BBH", code, ident, len(data) + 4) + data


def parse_control(raw):
    if len(raw) < 4:
        return None
    code, ident, size = struct.unpack_from("!BBH", raw)
    if size < 4 or size > len(raw):
        return None
    return code, ident, raw[4:size]


def parse_options(raw):
    result = []
    while raw:
        if len(raw) < 2 or raw[1] < 2 or raw[1] > len(raw):
            raise ValueError("Malformed PPP option")
        result.append((raw[0], raw[:raw[1]]))
        raw = raw[raw[1]:]
    if len({k for k, _ in result}) != len(result):
        raise ValueError("Duplicate PPP option")
    return result


class Session:
    def __init__(self, link, options, report):
        self.link, self.options, self.report, self.clock = link, options, report, link.clock
        self.mac, self.sid = None, 0
        self.mtu = self.local_mru = min(1492, link.mtu - 8)
        self.magic = secrets.randbits(32) or 1
        self.host = secrets.token_bytes(8)
        self.ident = secrets.randbelow(256)
        self.src_ip, self.peer_ip, self.dns = "0.0.0.0", None, []
        self.auth, self.auth_complete = None, False
        self.challenge_id, self.challenge_response = None, None
        self.peer_config, self.pending = {}, deque(maxlen=64)
        self.terminated, self.padt_sent = False, False

    def next_id(self):
        self.ident = (self.ident + 1) & 255
        return self.ident

    def send_discovery(self, code, tags, dst, sid=0):
        self.link.send(0x8863, envelope(code, sid, tags), dst)
        self.report.event("PPPoE", "TX", {9: "PADI", 0x19: "PADR", 0xa7: "PADT"}[code])

    def discover(self):
        service = self.options.service.encode("utf-8")
        padi = tag(0x0101, service) + tag(0x0103, self.host)
        selected = None
        for _ in range(self.options.retries + 1):
            self.send_discovery(9, padi, BROADCAST)
            end = self.clock() + self.options.timeout
            while self.clock() < end:
                frame = self.link.recv(end - self.clock())
                if frame is None:
                    break
                parsed = parse_envelope(frame.payload) if frame.ethertype == 0x8863 else None
                if not parsed or parsed[:2] != (7, 0) or frame.dst != self.link.mac:
                    continue
                try:
                    tags = parse_tags(parsed[2])
                except ValueError:
                    continue
                if tags.get(0x0103) != [self.host] or len(tags.get(0x0102, [])) != 1:
                    continue
                if service not in tags.get(0x0101, []):
                    continue
                if any(k in tags for k in (0x0201, 0x0202, 0x0203)):
                    continue
                if self.options.ac_name and tags[0x0102] != [self.options.ac_name.encode("utf-8")]:
                    continue
                if any(len(tags.get(k, [])) > 1 for k in (0x0104, 0x0110)):
                    continue
                selected, self.mac = tags, frame.src
                self.report.event("PPPoE", "RX", "PADO", ac=tags[0x0102][0].decode("utf-8", "replace"), mac=self.mac)
                break
            if selected:
                break
        if selected is None:
            raise ProbeTimeout("PADO timeout: check interface, VLAN, service name and AC")
        padr = padi + b"".join(tag(k, v) for k in (0x0104, 0x0110) for v in selected.get(k, []))
        for _ in range(self.options.retries + 1):
            self.send_discovery(0x19, padr, self.mac)
            end = self.clock() + self.options.timeout
            while self.clock() < end:
                frame = self.link.recv(end - self.clock())
                if frame is None:
                    break
                parsed = parse_envelope(frame.payload) if frame.ethertype == 0x8863 else None
                if not parsed or parsed[0] != 0x65 or frame.src != self.mac or frame.dst != self.link.mac:
                    continue
                try:
                    tags = parse_tags(parsed[2])
                except ValueError:
                    continue
                if tags.get(0x0103) != [self.host]:
                    continue
                if any(k in tags for k in (0x0201, 0x0202, 0x0203)):
                    raise ProbeError("PADS rejected by AC (service/system/generic error tag)")
                if parsed[1] in (0, 0xffff) or tags.get(0x0101) != [service]:
                    continue
                self.sid = parsed[1]
                self.report.event("PPPoE", "RX", "PADS", session_id=self.sid)
                return
        raise ProbeTimeout("PADS timeout")

    def send(self, proto, payload):
        self.link.send(0x8864, envelope(0, self.sid, struct.pack("!H", proto) + payload), self.mac)

    def send_control(self, proto, code, ident, data=b""):
        self.send(proto, control(code, ident, data))
        self.report.event(LABELS.get(proto, "PPP"), "TX", "Control packet", code=code, identifier=ident)

    def receive(self, timeout, wanted=None):
        if wanted is not None:
            for item in tuple(self.pending):
                if item[0] == wanted:
                    self.pending.remove(item)
                    return item
        end = self.clock() + max(0, timeout)
        while self.clock() < end:
            frame = self.link.recv(end - self.clock())
            if frame is None:
                return None
            if frame.src != self.mac or frame.dst != self.link.mac or frame.ethertype not in (0x8863, 0x8864):
                continue
            parsed = parse_envelope(frame.payload)
            if not parsed or parsed[1] != self.sid:
                continue
            code, _, payload = parsed
            if frame.ethertype == 0x8863:
                if code == 0xa7:
                    self.sid = 0
                    raise ProbeError("Peer closed PPPoE session with PADT")
                continue
            if code or len(payload) < 2 or len(payload) > self.local_mru + 2:
                continue
            proto = struct.unpack_from("!H", payload)[0]
            data = payload[2:]
            if proto == LCP:
                ctrl = parse_control(data)
                if ctrl and ctrl[0] == 5:
                    self.send_control(LCP, 6, ctrl[1], ctrl[2])
                    raise ProbeError("Peer terminated LCP")
                if ctrl and ctrl[0] == 9 and len(ctrl[2]) >= 4:
                    if self.magic == struct.unpack_from("!I", ctrl[2])[0]:
                        raise ProbeError("PPP loopback detected")
                    self.send_control(LCP, 10, ctrl[1], struct.pack("!I", self.magic) + ctrl[2][4:])
                    continue
                if ctrl and ctrl[0] in (7, 8):
                    raise ProbeError("Peer rejected a required PPP control/protocol packet")
            if wanted is not None and proto != wanted:
                if self.background(proto, data):
                    continue
                if proto in (PAP, CHAP, IPCP):
                    self.pending.append((proto, data))
                continue
            return proto, data
        return None

    def background(self, proto, data):
        ctrl = parse_control(data) if proto in (LCP, IPCP, CHAP, PAP) else None
        if proto in (LCP, IPCP) and ctrl and ctrl[0] == 1 and proto in self.peer_config:
            if ctrl[2] != self.peer_config[proto]:
                raise ProbeError(f"Peer restarted {LABELS[proto]} negotiation during test")
            self.send_control(proto, 2, ctrl[1], ctrl[2])
            return True
        if proto == CHAP and self.auth_complete and self.auth == "chap" and ctrl:
            if ctrl[0] == 1:
                self.respond_chap(ctrl[1], ctrl[2])
            elif ctrl[0] in (3, 4) and ctrl[1] == self.challenge_id:
                if ctrl[0] == 4:
                    raise ProbeError("CHAP reauthentication failed")
                self.challenge_id = None
            return True
        if proto in (LCP, IPCP, PAP):
            return bool(ctrl and ctrl[0] != 1)
        if proto not in (CHAP, IPV4):
            rejected = (struct.pack("!H", proto) + data)[:self.mtu - 4]
            self.send_control(LCP, 8, self.next_id(), rejected)
            return True
        return False

    def peer_request(self, proto, data):
        try:
            options = parse_options(data)
        except ValueError:
            return None
        reject, nak = [], []
        auth, peer_ip, peer_mru = None, None, 1492
        for kind, raw in options:
            if proto == LCP:
                if kind == 1 and len(raw) == 4:
                    value = struct.unpack_from("!H", raw, 2)[0]
                    if value < 128:
                        nak.append(b"\x01\x04" + struct.pack("!H", self.local_mru))
                    else:
                        peer_mru = min(value, 1492)
                elif kind == 3:
                    if raw == b"\x03\x04\xc0\x23":
                        auth = "pap"
                    elif raw == b"\x03\x05\xc2\x23\x05":
                        auth = "chap"
                    else:
                        raise ProbeError("Unsupported PPP authentication; only PAP and CHAP-MD5 are supported")
                elif kind == 5 and len(raw) == 6:
                    if struct.unpack_from("!I", raw, 2)[0] == self.magic:
                        nak.append(b"\x05\x06" + struct.pack("!I", self.magic ^ 0xffffffff))
                else:
                    reject.append(raw)
            elif kind == 3 and len(raw) == 6:
                try:
                    peer_ip = unicast_ip(ip_text(raw[2:]))
                except ValueError:
                    raise ProbeError("Peer requested an unusable IPCP address") from None
            else:
                reject.append(raw)
        if reject:
            return 4, b"".join(reject)
        if nak:
            return 3, b"".join(nak)
        if proto == LCP:
            self.auth, self.mtu = auth, min(peer_mru, self.link.mtu - 8)
        else:
            self.peer_ip = peer_ip
        self.peer_config[proto] = data
        return 2, data

    def adjust_request(self, proto, code, requested, response):
        original = dict(parse_options(requested))
        changed = parse_options(response)
        if not changed or any(k not in original for k, _ in changed):
            return None
        if code == 4:
            if any(original[k] != raw for k, raw in changed):
                return None
            for kind, _ in changed:
                if proto == IPCP and kind == 3:
                    raise ProbeError("Peer rejected IPCP address negotiation")
                original.pop(kind)
        else:
            for kind, raw in changed:
                if proto == LCP and kind == 1 and len(raw) == 4:
                    value = struct.unpack_from("!H", raw, 2)[0]
                    if not 128 <= value <= min(1492, self.link.mtu - 8):
                        raise ProbeError("Peer requested unsupported MRU")
                    self.local_mru = value
                elif proto == LCP and kind == 5 and len(raw) == 6:
                    self.magic = secrets.randbits(32) or 1
                    raw = b"\x05\x06" + struct.pack("!I", self.magic)
                elif proto == IPCP and kind in (3, 129, 131) and len(raw) == 6:
                    if kind == 3:
                        unicast_ip(ip_text(raw[2:]))
                else:
                    raise ProbeError("Unsupported PPP Configure-Nak option")
                original[kind] = raw
        return b"".join(original.values())

    def negotiate(self, proto):
        if proto == LCP:
            request = b"\x01\x04" + struct.pack("!H", self.local_mru) + b"\x05\x06" + struct.pack("!I", self.magic)
        else:
            request = b"\x03\x06\0\0\0\0\x81\x06\0\0\0\0\x83\x06\0\0\0\0"
        local_ok, peer_ok = False, False
        ident, attempts, rounds = self.next_id(), 0, 0
        deadline = self.clock() + self.options.timeout * (self.options.retries + 1) * 6
        resend = self.clock()
        while self.clock() < deadline:
            if local_ok and peer_ok:
                if proto == IPCP:
                    agreed = dict(parse_options(request))
                    self.src_ip = unicast_ip(ip_text(agreed[3][2:]))
                    self.dns = [ip_text(agreed[k][2:]) for k in (129, 131)
                                if k in agreed and agreed[k][2:] != b"\0" * 4]
                self.report.event(LABELS[proto], "OPEN", "Both directions acknowledged")
                return
            if not local_ok and self.clock() >= resend:
                if attempts > self.options.retries:
                    raise ProbeTimeout(f"{LABELS[proto]} Configure-Ack timeout")
                self.send_control(proto, 1, ident, request)
                attempts += 1
                resend = self.clock() + self.options.timeout
            wait_until = min(deadline, resend) if not local_ok else deadline
            incoming = self.receive(wait_until - self.clock(), proto)
            if incoming is None:
                continue
            parsed = parse_control(incoming[1])
            if not parsed:
                continue
            code, rid, data = parsed
            self.report.event(LABELS[proto], "RX", "Control packet", code=code, identifier=rid)
            if code == 1:
                response = self.peer_request(proto, data)
                if response:
                    self.send_control(proto, response[0], rid, response[1])
                    peer_ok = response[0] == 2
            elif code == 2 and rid == ident and data == request:
                local_ok = True
            elif code in (3, 4) and rid == ident and not local_ok:
                try:
                    revised = self.adjust_request(proto, code, request, data)
                except ValueError:
                    continue
                if revised is None:
                    continue
                rounds += 1
                if rounds > 12:
                    raise ProbeError(f"{LABELS[proto]} negotiation did not converge")
                request, ident, attempts, resend = revised, self.next_id(), 0, self.clock()
            elif code == 5:
                self.send_control(proto, 6, rid, data)
                raise ProbeError(f"Peer terminated {LABELS[proto]}")
        raise ProbeTimeout(f"{LABELS[proto]} bidirectional negotiation timeout")

    def respond_chap(self, ident, data):
        if not data or not data[0] or len(data) < 1 + data[0]:
            return False
        challenge = data[1:1 + data[0]]
        digest = hashlib.md5(bytes([ident]) + self.options.password.encode("utf-8") + challenge).digest()
        response = b"\x10" + digest + self.options.username.encode("utf-8")
        self.challenge_id, self.challenge_response = ident, response
        self.send_control(CHAP, 2, ident, response)
        return True

    def authenticate(self):
        if self.auth is None:
            self.auth_complete = True
            self.report.event("AUTH", "INFO", "AC did not request authentication")
            return
        username, password = self.options.username.encode("utf-8"), self.options.password.encode("utf-8")
        if len(username) > 255 or len(password) > 255:
            raise ValueError("PAP/CHAP credentials must be at most 255 UTF-8 bytes")
        proto, ident = (PAP if self.auth == "pap" else CHAP), self.next_id()
        request = bytes([len(username)]) + username + bytes([len(password)]) + password
        for _ in range(self.options.retries + 1):
            if proto == PAP:
                self.send_control(PAP, 1, ident, request)
            elif self.challenge_response is not None:
                self.send_control(CHAP, 2, self.challenge_id, self.challenge_response)
            end = self.clock() + self.options.timeout
            while self.clock() < end:
                incoming = self.receive(end - self.clock(), proto)
                if incoming is None:
                    break
                parsed = parse_control(incoming[1])
                if not parsed:
                    continue
                code, rid, data = parsed
                if proto == PAP and rid == ident and code in (2, 3):
                    if not data or data[0] > len(data) - 1:
                        continue
                    if code == 3:
                        raise ProbeError("PAP authentication failed")
                    self.auth_complete = True
                elif proto == CHAP:
                    if code == 1:
                        self.respond_chap(rid, data)
                    elif self.challenge_id is not None and rid == self.challenge_id and code in (3, 4):
                        if code == 4:
                            raise ProbeError("CHAP authentication failed")
                        self.auth_complete = True
                        self.challenge_id = None
                if self.auth_complete:
                    self.report.event("AUTH", "PASS", self.auth.upper() + " authentication succeeded")
                    return
        raise ProbeTimeout(self.auth.upper() + " authentication timeout")

    def prepare(self, target):
        unicast_ip(target)
        if target == self.src_ip:
            raise ValueError("PPP Ping target must not be the assigned local IP")

    def send_ip(self, packet):
        if len(packet) > self.mtu:
            raise ValueError("IPv4 packet exceeds negotiated PPP MRU")
        self.send(IPV4, packet)

    def recv_ip(self, timeout):
        end = self.clock() + max(0, timeout)
        while self.clock() < end:
            incoming = self.receive(end - self.clock())
            if incoming is None:
                return None
            proto, data = incoming
            if proto == IPV4:
                return data
            self.background(proto, data)
        return None

    def close(self):
        if not self.sid:
            return
        try:
            ident = self.next_id()
            self.send_control(LCP, 5, ident)
            end = self.clock() + self.options.timeout
            while self.clock() < end:
                incoming = self.receive(end - self.clock(), LCP)
                if incoming is None:
                    break
                ctrl = parse_control(incoming[1])
                if ctrl and ctrl[:2] == (6, ident):
                    self.terminated = True
                    self.report.event("LCP", "RX", "Terminate-Ack")
                    break
        except (ProbeError, OSError) as exc:
            self.report.event("CLEANUP", "WARN", str(exc))
        finally:
            if self.sid:
                try:
                    self.send_discovery(0xa7, b"", self.mac, self.sid)
                    self.padt_sent = True
                except (ProbeError, OSError) as exc:
                    self.report.event("CLEANUP", "ERROR", "Could not send PADT", reason=str(exc))
                self.sid = 0


def run_pppoe(link, options, report):
    session, result = Session(link, options, report), {}
    try:
        session.discover()
        session.negotiate(LCP)
        session.authenticate()
        session.negotiate(IPCP)
        result.update(ip=session.src_ip, peer_ip=session.peer_ip, dns=session.dns,
                      session_id=session.sid, ac_mac=session.mac, authentication=session.auth or "none", mtu=session.mtu)
        report.event("PPP-IP", "INFO", "IPCP addresses", **result)
        target = options.ping or session.peer_ip
        if not target:
            raise ValueError("AC supplied no peer IP; specify --ping with a numeric IPv4 address")
        result["ping"] = echo(session, target, options.count, options.interval, options.timeout, options.size, report)
        result["success"] = result["ping"]["success"]
    finally:
        session.close()
    result.update(terminate_ack=session.terminated, padt_sent=session.padt_sent)
    result["success"] = result["success"] and session.padt_sent
    return result
