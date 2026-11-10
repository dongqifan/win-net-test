import argparse
import getpass
import ipaddress
import math
import os
import sys
from pathlib import Path

from . import __version__
from .dhcp import run_dhcp
from .ping import run_ping
from .pppoe import run_pppoe
from .repeat import run_repeat
from .report import ProbeError, Report, safe_text
from .transport import Link, list_interfaces, select_interface
from .wire import random_mac, unicast_ip, validate_mac


def integer(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("Expected an integer") from None
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Expected {low}..{high}")
        return number
    return parse


def seconds(low, high):
    def parse(value):
        try:
            number = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError("Expected seconds") from None
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Expected finite seconds in {low}..{high}")
        return number
    return parse


def parser():
    root = argparse.ArgumentParser(description="Windows IPv4 DHCP / PPPoE / Ping raw Ethernet tester (Npcap)")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("interfaces", help="List Windows adapter indices, names, GUIDs and status")
    for name in ("dhcp", "pppoe", "ping", "repeat"):
        p = commands.add_parser(name, help={"dhcp": "DORA -> accelerated renew/rebind -> optional ping -> release",
                                          "pppoe": "Discovery -> LCP -> PAP/CHAP-MD5 -> IPCP -> ping -> disconnect",
                                          "ping": "Address conflict probe -> ARP -> ICMP Echo statistics",
                                          "repeat": "Repeat DISCOVER / PADI / Echo without waiting for responses"}[name])
        p.add_argument("--iface", required=True, help="Windows ifIndex, exact adapter name or Npcap GUID")
        p.add_argument("--vlan", type=integer(1, 4094), help="802.1Q VLAN; omit for untagged frames")
        p.add_argument("--pcp", type=integer(0, 7), default=0, help="802.1p priority (requires --vlan)")
        p.add_argument("--mac", type=validate_mac, help="Test source MAC; default: random locally administered MAC")
        p.add_argument("--timeout", type=seconds(.1, 120), default=3, help="Per-attempt timeout in seconds (default: 3)")
        p.add_argument("--retries", type=integer(0, 10), default=2, help="Additional protocol/ARP retries (default: 2)")
        p.add_argument("--json", type=Path, help="Write a NEW JSON report file")
        p.add_argument("--pcap", type=Path, help="Write a NEW capture file; may contain PAP plaintext credentials")
        if name in ("dhcp", "repeat"):
            p.add_argument("--broadcast", action="store_true",
                           help="DHCP: set BROADCAST reply flag (default clear; requests still broadcast)")
        if name == "repeat":
            p.add_argument("--protocol", choices=("dhcp", "pppoe", "ping"), required=True,
                           help="Send DHCP DISCOVER, PPPoE PADI, or ICMP Echo only")
            p.add_argument("--interval-ms", type=integer(100, 60000), default=1000,
                           help="Minimum send-start interval in milliseconds; default 1000, best effort")
            p.add_argument("--count", type=integer(0, 2147483647), default=0,
                           help="Packets to send; 0 (default) runs until Ctrl+C")
            p.add_argument("--hostname", help="DHCP hostname; default: win-net-test")
            p.add_argument("--service", help="PPPoE Service-Name; default: any service")
            p.add_argument("--src-ip", type=unicast_ip, help="Ping: unused static source IPv4")
            p.add_argument("--netmask", help="Ping: subnet mask or prefix length")
            p.add_argument("--gateway", type=unicast_ip, help="Ping: gateway for off-subnet targets")
            p.add_argument("--target", type=unicast_ip, help="Ping: numeric unicast IPv4 target")
            p.add_argument("--dst-mac", type=validate_mac, help="Ping: known next-hop MAC; skip ARP resolution")
            p.add_argument("--size", type=integer(8, 1472), help="Ping: ICMP data bytes; default 32")
            continue
        p.add_argument("--count", type=integer(1, 65535), default=4, help="Echo request count (default: 4)")
        p.add_argument("--interval", type=seconds(.05, 60), default=1, help="Minimum Echo start interval (seconds)")
        p.add_argument("--size", type=integer(8, 1472), default=32, help="ICMP data bytes, limited by interface/PPP MTU")
        if name == "dhcp":
            p.add_argument("--hostname", default="win-net-test", help="DHCP hostname (ASCII, at most 63 bytes)")
            p.add_argument("--renew-delay", type=seconds(0, 86400), default=0, help="Wait before accelerated renewal; must be less than lease")
            p.add_argument("--ping", type=unicast_ip, help="Optional numeric IPv4 target after renewal")
        elif name == "pppoe":
            p.add_argument("--username", required=True, help="PPP username")
            p.add_argument("--password-env", default="NETTEST_PPPOE_PASSWORD", help="Password environment variable; otherwise prompt without echo")
            p.add_argument("--service", default="", help="PPPoE Service-Name; default: any service")
            p.add_argument("--ac-name", help="Exact Access Concentrator name")
            p.add_argument("--ping", type=unicast_ip, help="Numeric IPv4 target; default: negotiated peer IP")
        else:
            p.add_argument("--src-ip", required=True, type=unicast_ip, help="Unused static IPv4 address for this test")
            p.add_argument("--netmask", required=True, help="Subnet mask or prefix length")
            p.add_argument("--gateway", type=unicast_ip, help="Gateway for an off-subnet target")
            p.add_argument("--target", required=True, type=unicast_ip, help="Numeric unicast IPv4 target")
    return root


def validate(options):
    if options.command == "interfaces":
        return
    if options.pcp and options.vlan is None:
        raise ValueError("--pcp requires --vlan")
    outputs = [p.resolve() for p in (options.json, options.pcap) if p]
    if len(outputs) != len(set(outputs)):
        raise ValueError("JSON and PCAP must use different paths")
    for path in outputs:
        if path.exists() or not path.parent.is_dir():
            raise ValueError(f"Output must be a new file with an existing parent directory: {path}")
    protocol = options.command
    if options.command == "repeat":
        protocol = options.protocol
        if options.broadcast and protocol != "dhcp":
            raise ValueError("--broadcast is only valid for repeat dhcp")
        allowed = {"dhcp": {"hostname"}, "pppoe": {"service"},
                   "ping": {"src_ip", "netmask", "gateway", "target", "dst_mac", "size"}}[protocol]
        for name in ("hostname", "service", "src_ip", "netmask", "gateway", "target", "dst_mac", "size"):
            if getattr(options, name) is not None and name not in allowed:
                raise ValueError(f"--{name.replace('_', '-')} is not valid for repeat {protocol}")
        if protocol == "ping" and any(getattr(options, name) is None for name in ("src_ip", "netmask", "target")):
            raise ValueError("repeat ping requires --src-ip, --netmask and --target")
        options.hostname = "win-net-test" if options.hostname is None else options.hostname
        options.service = "" if options.service is None else options.service
        options.size = 32 if options.size is None else options.size
        if len(options.service.encode("utf-8")) > 255:
            raise ValueError("Service name must be at most 255 UTF-8 bytes")
    if protocol == "dhcp":
        try:
            hostname = options.hostname.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("--hostname must be ASCII") from None
        if len(hostname) > 63 or any(c < 33 or c > 126 for c in hostname):
            raise ValueError("--hostname must contain at most 63 printable ASCII bytes")
    if options.command == "pppoe":
        if len(options.username.encode("utf-8")) > 255:
            raise ValueError("Username must be at most 255 UTF-8 bytes")
        if len(options.service.encode("utf-8")) > 255 or (options.ac_name and len(options.ac_name.encode("utf-8")) > 255):
            raise ValueError("Service/AC name must be at most 255 UTF-8 bytes")
    if protocol == "ping":
        network = ipaddress.IPv4Network(f"{options.src_ip}/{options.netmask}", strict=False)
        target = ipaddress.IPv4Address(options.target)
        if options.src_ip == options.target:
            raise ValueError("Target cannot equal the test source IP")
        if target not in network and not options.gateway:
            raise ValueError("--gateway is required for an off-subnet target")
        if options.gateway and ipaddress.IPv4Address(options.gateway) not in network:
            raise ValueError("Gateway must be inside the source subnet")
        if network.prefixlen < 31 and any(ipaddress.IPv4Address(value) in (network.network_address, network.broadcast_address)
                                         for value in (options.src_ip, options.target, options.gateway) if value):
            raise ValueError("Source, target and gateway must not be subnet network/broadcast addresses")


def main(argv=None):
    p = parser()
    try:
        options = p.parse_args(argv)
        validate(options)
    except SystemExit as exc:
        return exc.code
    except ValueError as exc:
        print("Argument error: " + safe_text(exc), file=sys.stderr)
        return 2
    report = Report(options.command, max_events=100 if options.command == "repeat" else None)
    link, code, active = None, 2, False
    try:
        interfaces = list_interfaces()
        if options.command == "interfaces":
            print("INDEX  NAME                     STATUS        MTU   MAC                DESCRIPTION / GUID")
            for i in interfaces:
                print(f"{i.index:<6} {safe_text(i.name):24} {i.status:12} {i.mtu:<5} {i.mac:18} {safe_text(i.description)} / {i.guid}")
            return 0
        interface = select_interface(interfaces, options.iface)
        if interface.status.casefold() != "up":
            raise ValueError("Selected adapter is not Up; connect the test cable first")
        if interface.media.casefold() not in ("802.3", "ethernet"):
            raise ValueError("Use a wired Ethernet adapter; Wi-Fi and loopback are not supported")
        if options.command == "pppoe":
            if options.password_env in os.environ:
                options.password = os.environ[options.password_env]
            elif sys.stdin.isatty():
                options.password = getpass.getpass("PPPoE password: ")
            else:
                raise ValueError("Set the password environment variable or run in an interactive terminal")
            if len(options.password.encode("utf-8")) > 255:
                raise ValueError("Password must be at most 255 UTF-8 bytes")
        mac = options.mac or random_mac()
        report.event("INTERFACE", "INFO", "Test interface", index=interface.index, name=interface.name,
                     test_mac=mac, vlan=options.vlan, pcp=options.pcp)
        if mac == interface.mac:
            report.event("SAFETY", "WARN", "Using the adapter MAC may conflict with the Windows network stack")
        if options.vlan:
            report.event("VLAN", "WARN", "Driver/offload may strip tags; wire-level VLAN delivery requires external verification")
        if options.pcap:
            report.event("PCAP", "WARN", "Capture may contain PAP plaintext password or CHAP material; protect this file")
        link = Link(interface, mac, options.vlan, options.pcp, options.pcap,
                    precise_timing=options.command == "repeat")
        active = True
        if options.command == "dhcp":
            result = run_dhcp(link, options, report)
        elif options.command == "pppoe":
            result = run_pppoe(link, options, report)
        elif options.command == "repeat":
            result = run_repeat(link, options, report)
        else:
            result = run_ping(link, options.src_ip, options.target, options.netmask, options.gateway,
                              options.count, options.interval, options.timeout, options.size, report, options.retries)
        result["capture_dropped"] = link.dropped
        success = result["success"] and not link.dropped
        code = 0 if success else 1
        report.finish(success, result, None if success else "Protocol test failed, packets lost, or capture queue overflowed")
    except KeyboardInterrupt:
        code = 130
        report.finish(False, error="Repeat sending interrupted; partial statistics saved" if options.command == "repeat"
                      else "Interrupted; attempted protocol cleanup")
    except (ProbeError, OSError, ValueError, ImportError, EOFError, TimeoutError) as exc:
        code = 1 if active and isinstance(exc, ProbeError) else 2
        report.finish(False, error=str(exc))
    finally:
        if link:
            try:
                link.close()
            except Exception as exc:
                report.event("CAPTURE", "ERROR", "Failed to close capture", reason=str(exc))
                report.data["success"] = False
                if code == 0:
                    code = 2
        if getattr(options, "json", None):
            try:
                report.save(options.json)
            except OSError as exc:
                print("Cannot save report: " + safe_text(exc), file=sys.stderr)
                code = 2
        if hasattr(options, "password"):
            options.password = ""
    return code
