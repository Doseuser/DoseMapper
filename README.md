```markdown
# DoseMapper

A high-speed, asynchronous network scanner built for performance and flexibility.  
DoseMapper blends the raw speed of stateless SYN scanning with rich service detection and OS fingerprinting — all in pure Python 3.10+.

It’s my personal experiment in writing a scanner that doesn't feel sluggish when you throw a /16 at it. Hope you find it useful.

— doseuser

## Features

- **Blazing fast TCP SYN scan** (stateless, requires root/CAP_NET_RAW)  
  Handles thousands of ports per second with built-in rate limiting.

- **Fallback TCP connect scan** for unprivileged users or Windows/macOS.

- **UDP scan** with ICMP unreachable detection.

- **Host discovery** using ICMP echo + TCP SYN to common ports.

- **Stealth & evasion**  
  Random source ports, decoy IP support, adjustable data length, and packet fragmentation (MTU).

- **Service version detection**  
  Banner grabbing + regex signatures for SSH, HTTP, FTP, MySQL, PostgreSQL, Redis, MongoDB, and more.

- **OS fingerprinting** (inspired by p0f) using TTL and TCP window size.

- **Live progress & pretty tables** thanks to Rich.

- **Flexible output** – JSON, CSV, plain text, or all three at once (`-oA`).

- **Rate limiting** with token bucket to respect your bandwidth.

- **Parallel DNS resolution** for hostnames and ranges.

## Requirements

- Python 3.10 or newer
- Linux for raw socket features (SYN & UDP scans)  
  Root privileges or `CAP_NET_RAW` capability are required for those scans.
- Third-party libraries (install via pip):

```bash
pip install scapy rich
```

> `aiodns` is optional – it speeds up DNS resolution but isn’t mandatory.

## Quick start

Clone or download the single `dosemapper.py` file.

### Basic connect scan (works everywhere)

```bash
python3 dosemapper.py 192.168.1.1 -p 22,80,443 --connect
```

### Fast SYN scan (Linux with root)

```bash
sudo python3 dosemapper.py 192.168.1.0/24 -p 1-1000 --syn --rate 5000
```

### Scan with service detection and OS fingerprinting

```bash
sudo python3 dosemapper.py scanme.nmap.org -p 22,80,443 --syn --sV --os
```

### Stealthy scan with decoys and fragmentation

```bash
sudo python3 dosemapper.py 10.0.0.5 -p 80,443 --syn --stealth --decoy 10.0.0.1 10.0.0.2 --data-length 40 --mtu 200
```

### Host discovery before scan

```bash
sudo python3 dosemapper.py 10.0.0.0/24 --discover -p 80 --syn
```

### Output all formats

```bash
python3 dosemapper.py example.com -p 1-100 --connect -oA results
```

This creates `results.json`, `results.csv`, and `results.txt`.

## Command line reference

```
usage: dosemapper.py target -p ports [options]

Positional:
  target                  IP, CIDR, range, or hostname

Required:
  -p, --ports             Port list (e.g. 80, 1-1000)

Scan types (choose one):
  --syn                   TCP SYN scan (root)
  --connect               TCP connect scan (default)
  --udp                   UDP scan

Performance:
  --rate N                Packets per second
  --max-parallel N        Max concurrent connections (default 1000)
  --timeout S             Timeout per probe (default 3.0)
  --retries N             Retries (default 1)

Stealth & evasion:
  --stealth               Enable random delays and frag
  --decoy IP [IP ...]     Spoofed source IPs
  --randomize-src         Randomize source port
  --data-length N         Append random bytes
  --mtu N                 Fragment packets to N
  --fragment              Enable fragmentation

Detection:
  --discover              Host discovery (ICMP + TCP)
  --os                    OS fingerprinting
  --sV                    Service version detection

Output:
  -oN BASE                Output base filename
  -oA BASE                Output all formats
  --output-format {json,csv,txt}

Other:
  --interface IFACE       Network interface
  --no-color              Disable colored output
```

## Notes

- SYN and UDP scans need raw sockets; run with `sudo` or grant `CAP_NET_RAW` to the Python binary.
- On Windows and macOS, the tool will fall back to connect scan with a warning.
- The scanner’s speed depends on your network and the rate you set. Too high a rate may cause packet loss or trigger IDS.
- Decoy addresses must be reachable by your machine (the OS must handle them) – not all networks will forward them.
- Service detection currently works on TCP open ports and uses a small signature database. Feel free to extend `SERVICE_PATTERNS` in the code.

## Why another scanner?

Because I wanted to play with `asyncio` and raw packets while building something actually useful. Nmap is great, but DoseMapper is lighter, hackable, and shows what you can do with modern Python.

## License

MIT – do whatever you want, just keep the original attribution if you republish.

---

Pull requests, issues, and ideas are welcome. Have fun mapping your network!
```
