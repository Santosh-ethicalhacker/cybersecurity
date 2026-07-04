# Vulnerability Scanner (Mini Project)

A simple Python script that scans a target host for common vulnerabilities.

## Key Features
- Scans a target for open ports (common ports by default, or a custom range)
- Grabs service banners and flags outdated software versions
- Flags inherently risky exposed services (Telnet, SMB, RDP, VNC, etc.)
- For web services (HTTP/HTTPS), checks for missing security headers and weak TLS
- Generates a plain-text vulnerability report

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py <target> [--ports 1-1024] [--output report.txt]
```

Examples:

```bash
# Scan common ports on a target
python scanner.py scanme.nmap.org

# Scan a custom port range
python scanner.py 192.168.1.10 --ports 1-65535

# Custom report location
python scanner.py example.com --output scans/example_report.txt
```

## Output

The script prints progress to the console and writes a report (`report.txt`
by default) containing:
- List of open ports and their banners
- Findings (risky services, outdated versions, missing security headers, weak TLS)
- A summary count of high-risk vs. outdated vs. other findings

## Disclaimer

**Only scan systems you own or have explicit written permission to test.**
Unauthorized port scanning or vulnerability scanning may be illegal in your
jurisdiction. This tool is for educational purposes (learning the basics of
penetration testing and vulnerability assessment).
