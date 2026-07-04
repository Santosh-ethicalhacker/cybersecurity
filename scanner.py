#!/usr/bin/env python3
"""
Vulnerability Scanner (Mini Project)
-------------------------------------
Scans a target host for:
  1. Open ports (against a list of commonly-exploited ports)
  2. Weak/known-risky service banners (basic version detection)
  3. A handful of simple web-app misconfiguration checks (if HTTP/HTTPS is open)

Generates a plain-text vulnerability report at the end.

Usage:
    python scanner.py <target> [--ports 1-1024] [--output report.txt]

Example:
    python scanner.py scanme.nmap.org
    python scanner.py 192.168.1.10 --ports 1-65535

NOTE: Only scan systems you own or have explicit written permission to test.
Unauthorized scanning may be illegal in your jurisdiction.
"""

import argparse
import socket
import ssl
import sys
from datetime import datetime

import requests

# Common ports and the service usually associated with them
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Services that are inherently risky if exposed to the internet
RISKY_IF_OPEN = {
    21: "FTP often transmits credentials in plaintext.",
    23: "Telnet is unencrypted; use SSH instead.",
    139: "NetBIOS can leak host/user info and is an old attack surface.",
    445: "SMB has a long history of critical RCE vulnerabilities (e.g. EternalBlue).",
    3389: "RDP exposed to the internet is a common ransomware entry point.",
    5900: "VNC is frequently run with weak/no authentication.",
}

# Very old / clearly outdated server banners worth flagging (illustrative, not exhaustive)
OUTDATED_BANNER_HINTS = [
    "Apache/1.",
    "Apache/2.0",
    "Apache/2.2",
    "nginx/1.0",
    "nginx/1.1",
    "OpenSSH_4",
    "OpenSSH_5",
    "OpenSSH_6.0",
    "Microsoft-IIS/6.0",
    "Microsoft-IIS/7.0",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
]


def parse_port_range(port_range: str):
    if "-" in port_range:
        start, end = port_range.split("-", 1)
        return range(int(start), int(end) + 1)
    return [int(port_range)]


def scan_port(target: str, port: int, timeout: float = 0.6):
    """Return the banner string if the port is open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result != 0:
                return None
            banner = ""
            try:
                sock.settimeout(1.0)
                banner = sock.recv(256).decode(errors="ignore").strip()
            except (socket.timeout, OSError):
                pass
            return banner or "(no banner)"
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)
    except OSError:
        return None


def check_http_headers(target: str, port: int, use_https: bool):
    """Check for missing common security headers on a web service."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}:{port}/"
    findings = []
    try:
        resp = requests.get(url, timeout=4, verify=False)
        missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
        if missing:
            findings.append(
                f"Missing security headers on {url}: {', '.join(missing)}"
            )
        server_header = resp.headers.get("Server")
        if server_header:
            findings.append(f"Server header discloses software: '{server_header}'")
    except requests.RequestException as e:
        findings.append(f"Could not fully probe {url} ({e.__class__.__name__})")
    return findings


def check_tls(target: str, port: int):
    """Basic TLS certificate / protocol sanity check for HTTPS-like ports."""
    findings = []
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(f"Outdated TLS protocol in use: {proto}")
                if not cert:
                    findings.append("Server presented no certificate (or self-signed, unverifiable).")
    except Exception as e:
        findings.append(f"TLS check failed: {e.__class__.__name__}")
    return findings


def run_scan(target: str, ports):
    open_ports = {}
    print(f"[*] Scanning {target} ({len(list(ports))} ports)...")
    ports = list(ports)  # re-materialize since we consumed it above for the print
    for port in ports:
        banner = scan_port(target, port)
        if banner is not None:
            service = COMMON_PORTS.get(port, "Unknown")
            open_ports[port] = {"service": service, "banner": banner}
            print(f"    [+] Port {port} ({service}) is OPEN")
    return open_ports


def analyze(target: str, open_ports: dict):
    findings = []

    for port, info in open_ports.items():
        service = info["service"]
        banner = info["banner"]

        if port in RISKY_IF_OPEN:
            findings.append(
                f"[RISK] Port {port} ({service}) is open. {RISKY_IF_OPEN[port]}"
            )

        for hint in OUTDATED_BANNER_HINTS:
            if hint in banner:
                findings.append(
                    f"[OUTDATED] Port {port} ({service}) banner suggests an old version: '{banner}'"
                )

        if port == 80:
            findings.extend(check_http_headers(target, port, use_https=False))
        if port in (443, 8443):
            findings.extend(check_http_headers(target, port, use_https=True))
            findings.extend(check_tls(target, port))

    return findings


def write_report(target: str, open_ports: dict, findings: list, output_path: str):
    with open(output_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("VULNERABILITY SCAN REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target:    {target}\n")
        f.write(f"Scan Time: {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Open Ports Found: {len(open_ports)}\n\n")

        f.write("-- Open Ports --\n")
        if open_ports:
            for port, info in sorted(open_ports.items()):
                f.write(f"  Port {port:<6} {info['service']:<12} Banner: {info['banner']}\n")
        else:
            f.write("  None found.\n")

        f.write("\n-- Findings --\n")
        if findings:
            for i, finding in enumerate(findings, 1):
                f.write(f"  {i}. {finding}\n")
        else:
            f.write("  No notable issues detected by this scanner.\n")

        f.write("\n-- Summary --\n")
        risk_count = sum(1 for f_ in findings if f_.startswith("[RISK]"))
        outdated_count = sum(1 for f_ in findings if f_.startswith("[OUTDATED]"))
        f.write(f"  High-risk exposed services: {risk_count}\n")
        f.write(f"  Outdated software banners:  {outdated_count}\n")
        f.write(f"  Other findings:             {len(findings) - risk_count - outdated_count}\n")

    print(f"\n[*] Report written to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Simple vulnerability scanner (mini project).")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "--ports",
        default=None,
        help="Port or port range to scan, e.g. '1-1024'. Defaults to a common-ports list.",
    )
    parser.add_argument(
        "--output",
        default="report.txt",
        help="Path to write the report to (default: report.txt)",
    )
    args = parser.parse_args()

    ports = parse_port_range(args.ports) if args.ports else COMMON_PORTS.keys()

    open_ports = run_scan(args.target, ports)
    findings = analyze(args.target, open_ports)
    write_report(args.target, open_ports, findings, args.output)


if __name__ == "__main__":
    main()
