#!/usr/bin/env python3
#Doseuser - DoseMapper
import argparse
import asyncio
import csv
import ipaddress
import json
import os
import random
import re
import signal
import socket
import struct
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from rich.console import Console
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, sr1, send, sniff, AsyncSniffer, RandShort, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("scapy not installed. SYN/UDP/ICMP scans will not work.")
    sys.exit(1)

console = Console()

SERVICE_PATTERNS = {
    22: [
        (r'SSH-([\d.]+)', 'ssh', None),
        (r'OpenSSH_([\d.]+)', 'openssh', None),
    ],
    80: [
        (r'Server:\s*([^\r\n]+)', 'http', 'Server'),
        (r'<title>(.*?)</title>', 'http', 'Title'),
    ],
    443: [
        (r'Server:\s*([^\r\n]+)', 'https', 'Server'),
    ],
    21: [
        (r'220[-\s]([^\r\n]+)', 'ftp', 'Banner'),
    ],
    25: [
        (r'220[-\s]([^\r\n]+)', 'smtp', 'Banner'),
    ],
    110: [
        (r'\+OK[-\s]([^\r\n]+)', 'pop3', 'Banner'),
    ],
    143: [
        (r'\* OK[-\s]([^\r\n]+)', 'imap', 'Banner'),
    ],
    3306: [
        (r'([\d.]+)\x00', 'mysql', 'Version'),
    ],
    5432: [
        (r'([\d.]+)', 'postgresql', 'Version'),
    ],
    6379: [
        (r'redis_version:([\d.]+)', 'redis', 'Version'),
    ],
    27017: [
        (r'version:[\s\"]*([\d.]+)', 'mongodb', 'Version'),
    ],
}

OS_FINGERPRINTS = [
    {
        'os': 'Linux (modern, 2.6+)',
        'ttl': [64],
        'wsize': [5840, 29200, 65535],
    },
    {
        'os': 'Windows XP/2000',
        'ttl': [128],
        'wsize': [65535],
    },
    {
        'os': 'Windows 7/10/11/Server',
        'ttl': [128],
        'wsize': [8192, 16384, 64240],
    },
    {
        'os': 'FreeBSD 9+',
        'ttl': [64],
        'wsize': [65535],
    },
    {
        'os': 'OpenBSD',
        'ttl': [64],
        'wsize': [16384],
    },
    {
        'os': 'Cisco IOS',
        'ttl': [255],
        'wsize': [4128],
    },
    {
        'os': 'Solaris 10',
        'ttl': [255],
        'wsize': [65535],
    },
]


@dataclass
class ScanResult:
    ip: str
    port: int
    protocol: str
    state: str = "unknown"
    service: str = ""
    version: str = ""
    os_guess: str = ""
    banner: str = ""
    ttl: int = 0
    wsize: int = 0


class RateLimiter:
    def __init__(self, rate: float, burst: int = 10):
        self.rate = max(1, rate)
        self.burst = burst
        self.tokens = burst
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.updated = now
            if self.tokens >= 1:
                self.tokens -= 1
                return
            wait = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait)
            self.tokens = 0
            self.updated = time.monotonic()


class TargetParser:
    @staticmethod
    def parse(target: str) -> List[str]:
        targets = []
        try:
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            if not targets:
                targets = [str(network.network_address)]
            return targets
        except ValueError:
            pass
        try:
            ip = ipaddress.ip_address(target)
            return [str(ip)]
        except ValueError:
            pass
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(TargetParser._resolve(target))

    @staticmethod
    async def _resolve(hostname: str) -> List[str]:
        try:
            addrs = await asyncio.get_event_loop().getaddrinfo(
                hostname, None, family=socket.AF_INET
            )
            return list(set(addr[4][0] for addr in addrs))
        except socket.gaierror:
            return []

    @staticmethod
    def parse_ports(port_spec: str) -> List[int]:
        ports = set()
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-', 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(p for p in ports if 1 <= p <= 65535)


class AsyncScanner:
    def __init__(self, args):
        self.args = args
        self.targets: List[str] = []
        self.ports: List[int] = []
        self.results: Dict[Tuple[str, int, str], ScanResult] = {}
        self.live_results: List[ScanResult] = []
        self.output_lock = asyncio.Lock()
        self.rate_limiter = RateLimiter(args.rate) if args.rate else None
        self.global_progress = 0
        self.total_tasks = 0
        self.sniffer_stop = asyncio.Event()
        self.syn_queue: asyncio.Queue = asyncio.Queue()
        self.udp_queue: asyncio.Queue = asyncio.Queue()

    async def resolve_dns_batch(self, hostnames: List[str]) -> Dict[str, str]:
        results = {}
        sem = asyncio.Semaphore(500)
        async def resolve_one(host):
            async with sem:
                try:
                    addrs = await asyncio.get_event_loop().getaddrinfo(
                        host, None, family=socket.AF_INET
                    )
                    if addrs:
                        results[host] = addrs[0][4][0]
                except Exception:
                    pass
        await asyncio.gather(*[resolve_one(h) for h in hostnames])
        return results

    async def host_discovery(self, targets: List[str]) -> List[str]:
        if not self.args.discover:
            return targets
        discovered = []
        ping_tasks = []
        sem = asyncio.Semaphore(1000)
        async def ping_host(ip):
            async with sem:
                try:
                    pkt = IP(dst=ip)/ICMP()
                    resp = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: sr1(pkt, timeout=0.5, verbose=0)
                    )
                    if resp:
                        discovered.append(ip)
                        return
                    syn_pkt = IP(dst=ip)/TCP(dport=[80, 443], flags='S', sport=RandShort())
                    resp = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: sr1(syn_pkt, timeout=0.5, verbose=0)
                    )
                    if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12:
                        discovered.append(ip)
                except Exception:
                    pass
        await asyncio.gather(*[ping_host(t) for t in targets])
        return list(set(discovered))

    async def syn_scan(self):
        if not os.geteuid() == 0:
            console.print("[red]SYN scan requires root privileges. Falling back to connect scan.[/red]")
            await self.connect_scan()
            return
        conf.iface = self.args.interface if self.args.interface else conf.iface
        self.total_tasks = len(self.targets) * len(self.ports)
        self.global_progress = 0
        send_sem = asyncio.Semaphore(1000)
        dest_ports = set(self.ports)
        use_decoy = self.args.decoy and len(self.args.decoy) > 0
        decoy_ips = self.args.decoy if use_decoy else []
        data_len = self.args.data_length if self.args.data_length else 0

        def packet_filter(pkt):
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return False
            tcp = pkt[TCP]
            ip_src = pkt[IP].src
            dport = tcp.sport
            return (
                ip_src in self.targets
                and dport in dest_ports
                and (tcp.flags & 0x12) != 0
            )

        def sniff_thread():
            try:
                sniff(
                    iface=conf.iface,
                    filter="tcp",
                    prn=lambda p: self.syn_queue.put_nowait(p),
                    store=0,
                    timeout=None,
                    stop_filter=lambda _: self.sniffer_stop.is_set()
                )
            except Exception:
                pass

        loop = asyncio.get_event_loop()
        sniffer_task = loop.run_in_executor(None, sniff_thread)

        async def send_syn(ip, port):
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            src_ip = ip
            src_port = random.randint(1024, 65535) if self.args.randomize_src else 12345
            if self.args.decoy:
                for decoy in decoy_ips:
                    pkt_decoy = IP(src=decoy, dst=ip)/TCP(sport=src_port, dport=port, flags='S')
                    if data_len:
                        pkt_decoy = pkt_decoy / (b'\x00' * data_len)
                    send(pkt_decoy, verbose=0)
            pkt = IP(src=src_ip, dst=ip)/TCP(sport=src_port, dport=port, flags='S')
            if data_len:
                pkt = pkt / (b'\x00' * data_len)
            if self.args.fragment and self.args.mtu:
                pkt = pkt.__class__(bytes(pkt))
                pkt[IP].frag = 1
                pkt[IP].flags |= 0x1 if self.args.mtu > 0 else 0
                pkt[IP].frag = 0
            send(pkt, verbose=0)
            self.global_progress += 1

        send_tasks = [
            send_syn(ip, port)
            for ip in self.targets
            for port in self.ports
        ]
        await asyncio.gather(*send_tasks)
        self.sniffer_stop.set()
        await asyncio.sleep(1)
        sniffer_task.cancel()
        while not self.syn_queue.empty():
            pkt = self.syn_queue.get_nowait()
            await self.process_syn_response(pkt)

    async def process_syn_response(self, pkt):
        ip_src = pkt[IP].src
        tcp = pkt[TCP]
        port = tcp.sport
        flags = tcp.flags
        state = "open" if (flags & 0x12) == 0x12 else "closed"
        ttl = pkt[IP].ttl
        wsize = tcp.window
        result = ScanResult(ip=ip_src, port=port, protocol='tcp', state=state)
        if state == "open":
            result.ttl = ttl
            result.wsize = wsize
        async with self.output_lock:
            key = (ip_src, port, 'tcp')
            if key not in self.results or state == "open":
                self.results[key] = result
                self.live_results.append(result)

    async def connect_scan(self):
        sem = asyncio.Semaphore(self.args.max_parallel or 1000)
        timeout = self.args.timeout or 3.0
        tasks = []
        self.total_tasks = len(self.targets) * len(self.ports)
        self.global_progress = 0

        async def connect_one(ip, port):
            async with sem:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    state = "open"
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    state = "closed"
                result = ScanResult(ip=ip, port=port, protocol='tcp', state=state)
                async with self.output_lock:
                    key = (ip, port, 'tcp')
                    self.results[key] = result
                    self.live_results.append(result)
                self.global_progress += 1

        for ip in self.targets:
            for port in self.ports:
                tasks.append(connect_one(ip, port))
        await asyncio.gather(*tasks)

    async def udp_scan(self):
        if not os.geteuid() == 0:
            console.print("[red]UDP scan requires root privileges. Skipping.[/red]")
            return
        conf.iface = self.args.interface if self.args.interface else conf.iface
        self.total_tasks = len(self.targets) * len(self.ports)
        self.global_progress = 0
        send_sem = asyncio.Semaphore(1000)

        def sniff_thread():
            try:
                sniff(
                    iface=conf.iface,
                    filter="icmp",
                    prn=lambda p: self.udp_queue.put_nowait(p),
                    store=0,
                    timeout=None,
                    stop_filter=lambda _: self.sniffer_stop.is_set()
                )
            except Exception:
                pass

        loop = asyncio.get_event_loop()
        sniffer_task = loop.run_in_executor(None, sniff_thread)

        async def send_udp(ip, port):
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            pkt = IP(dst=ip)/UDP(sport=RandShort(), dport=port)
            send(pkt, verbose=0)
            self.global_progress += 1

        send_tasks = [send_udp(ip, port) for ip in self.targets for port in self.ports]
        await asyncio.gather(*send_tasks)
        await asyncio.sleep(2)
        self.sniffer_stop.set()
        sniffer_task.cancel()

        while not self.udp_queue.empty():
            pkt = self.udp_queue.get_nowait()
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 3 and pkt[ICMP].code == 3:
                original = pkt[ICMP].payload
                if original.haslayer(IP) and original.haslayer(UDP):
                    ip_src = pkt[IP].src
                    port = original[UDP].sport
                    result = ScanResult(ip=ip_src, port=port, protocol='udp', state='closed')
                    async with self.output_lock:
                        key = (ip_src, port, 'udp')
                        self.results[key] = result
                        self.live_results.append(result)
        for ip in self.targets:
            for port in self.ports:
                key = (ip, port, 'udp')
                if key not in self.results:
                    result = ScanResult(ip=ip, port=port, protocol='udp', state='open|filtered')
                    self.results[key] = result
                    self.live_results.append(result)

    async def service_detect(self):
        sem = asyncio.Semaphore(100)
        open_ports = [
            (res.ip, res.port) for res in self.live_results
            if res.state == 'open' and res.protocol == 'tcp'
        ]
        tasks = []
        for ip, port in open_ports:
            tasks.append(self.detect_single_service(ip, port, sem))
        await asyncio.gather(*tasks)

    async def detect_single_service(self, ip: str, port: int, sem):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=2.0
                )
                banner = b""
                try:
                    banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
                writer.close()
                await writer.wait_closed()
                text = banner.decode('utf-8', errors='ignore')
                patterns = SERVICE_PATTERNS.get(port, [])
                service_name = ""
                version = ""
                for regex, svc, label in patterns:
                    m = re.search(regex, text, re.IGNORECASE)
                    if m:
                        service_name = svc
                        version = m.group(1).strip() if m.lastindex >= 1 else ""
                        break
                async with self.output_lock:
                    for i, res in enumerate(self.live_results):
                        if res.ip == ip and res.port == port and res.protocol == 'tcp':
                            res.service = service_name or 'unknown'
                            res.version = version
                            res.banner = text[:100]
                            break
            except Exception:
                pass

    def os_fingerprint(self):
        for res in self.live_results:
            if res.state == 'open' and res.ttl and res.wsize:
                best = None
                for fp in OS_FINGERPRINTS:
                    if res.ttl in fp['ttl'] and res.wsize in fp['wsize']:
                        res.os_guess = fp['os']
                        best = res.os_guess
                        break
                if not best:
                    res.os_guess = "unknown"

    async def run(self):
        self.targets = TargetParser.parse(self.args.target)
        if not self.targets:
            console.print("[red]Could not resolve target.[/red]")
            return
        self.ports = TargetParser.parse_ports(self.args.ports)
        if not self.ports:
            console.print("[red]No valid ports specified.[/red]")
            return
        console.print(f"[bold]Targets:[/bold] {len(self.targets)} host(s)")
        console.print(f"[bold]Ports:[/bold] {len(self.ports)} port(s)")

        if self.args.discover:
            self.targets = await self.host_discovery(self.targets)
            console.print(f"[bold]Discovered hosts:[/bold] {len(self.targets)}")

        scan_mode = 'connect'
        if self.args.udp:
            scan_mode = 'udp'
            await self.udp_scan()
        elif self.args.syn:
            scan_mode = 'syn'
            await self.syn_scan()
        else:
            await self.connect_scan()

        if self.args.service_version and scan_mode in ('syn', 'connect'):
            await self.service_detect()

        if self.args.os_detect and scan_mode in ('syn',):
            self.os_fingerprint()

        self.display_results()
        self.save_output()

    def display_results(self):
        table = Table(title="DoseMapper Scan Results", expand=True)
        table.add_column("IP", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("Proto", style="green")
        table.add_column("State", style="yellow")
        table.add_column("Service", style="blue")
        table.add_column("Version", style="blue")
        table.add_column("OS Guess", style="red")
        for res in self.live_results:
            state_style = "[green]open[/green]" if res.state == 'open' else "[red]closed[/red]"
            table.add_row(
                res.ip,
                str(res.port),
                res.protocol,
                state_style,
                res.service or "-",
                res.version or "-",
                res.os_guess or "-"
            )
        console.print(table)

    def save_output(self):
        if not self.args.output:
            return
        base = self.args.output
        if self.args.output_all:
            self._write_json(f"{base}.json")
            self._write_csv(f"{base}.csv")
            self._write_txt(f"{base}.txt")
        else:
            fmt = self.args.output_format or 'txt'
            if fmt == 'json':
                self._write_json(f"{base}.json")
            elif fmt == 'csv':
                self._write_csv(f"{base}.csv")
            else:
                self._write_txt(f"{base}.txt")

    def _write_json(self, path):
        with open(path, 'w') as f:
            json.dump([vars(r) for r in self.live_results], f, indent=2)
        console.print(f"JSON output saved to {path}")

    def _write_csv(self, path):
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=vars(self.live_results[0]).keys())
            writer.writeheader()
            for r in self.live_results:
                writer.writerow(vars(r))
        console.print(f"CSV output saved to {path}")

    def _write_txt(self, path):
        with open(path, 'w') as f:
            for r in self.live_results:
                f.write(f"{r.ip}:{r.port}/{r.protocol} - {r.state}\n")
        console.print(f"Text output saved to {path}")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="DoseMapper - Advanced network scanner"
    )
    parser.add_argument("target", help="Target IP, range, CIDR, or hostname")
    parser.add_argument("-p", "--ports", required=True, help="Port specification (e.g. 80, 1-1000)")
    parser.add_argument("--syn", action="store_true", help="TCP SYN scan (requires root)")
    parser.add_argument("--connect", action="store_true", help="TCP connect scan (default if no --syn)")
    parser.add_argument("--udp", action="store_true", help="UDP scan")
    parser.add_argument("--rate", type=float, help="Packet rate (packets per second)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth features (random delays, frag)")
    parser.add_argument("--decoy", nargs="+", help="Decoy IP addresses for SYN scan")
    parser.add_argument("--randomize-src", action="store_true", help="Randomize source port")
    parser.add_argument("--data-length", type=int, default=0, help="Append random data to packets")
    parser.add_argument("--mtu", type=int, help="Fragment packets to specified MTU")
    parser.add_argument("--fragment", action="store_true", help="Enable IP fragmentation")
    parser.add_argument("--discover", action="store_true", help="Host discovery (ICMP+TCP)")
    parser.add_argument("--os", dest="os_detect", action="store_true", help="OS fingerprinting")
    parser.add_argument("--sV", dest="service_version", action="store_true", help="Service/version detection")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout per probe (seconds)")
    parser.add_argument("--retries", type=int, default=1, help="Max retries")
    parser.add_argument("--max-parallel", type=int, default=1000, help="Max parallel connections")
    parser.add_argument("-oN", "--output", help="Output file base name")
    parser.add_argument("-oA", "--output-all", action="store_true", help="Output all formats (json,csv,txt)")
    parser.add_argument("--output-format", choices=['json', 'csv', 'txt'], help="Output format if -oN used")
    parser.add_argument("--interface", help="Network interface for sending packets")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    return parser


async def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.no_color:
        console.no_color = True
    if not (args.syn or args.connect or args.udp):
        args.connect = True
    scanner = AsyncScanner(args)
    try:
        await scanner.run()
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user.[/red]")
        scanner.display_results()
        scanner.save_output()
    except Exception as e:
        console.print_exception()


if __name__ == "__main__":
    asyncio.run(main())
