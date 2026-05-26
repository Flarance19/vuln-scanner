#!/usr/bin/env python3
"""
VulnScan - Web Application & Network Vulnerability Scanner
A lightweight penetration testing toolkit for educational purposes.
"""

import socket
import ssl
import json
import sys
import re
import datetime
import urllib.request
import urllib.error
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional

# ─── Data Structures ────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str
    scan_time: str = ""
    open_ports: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    tls_info: dict = field(default_factory=dict)
    software_versions: list = field(default_factory=list)

# ─── Port Scanner ────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

RISKY_PORTS = {
    23: ("CRITICAL", "Telnet is unencrypted — credentials sent in plaintext"),
    21: ("HIGH",     "FTP transmits data unencrypted; prefer SFTP/FTPS"),
    3389: ("HIGH",   "RDP exposed to internet — brute-force target"),
    5900: ("HIGH",   "VNC exposed — ensure strong password and encryption"),
    6379: ("HIGH",   "Redis open — often unauthenticated by default"),
    27017: ("HIGH",  "MongoDB open — check authentication is enabled"),
    445: ("MEDIUM",  "SMB exposed — ensure patched against EternalBlue"),
    25:  ("MEDIUM",  "SMTP open — verify relay not allowed"),
    3306: ("MEDIUM", "MySQL exposed — restrict to localhost if possible"),
    5432: ("MEDIUM", "PostgreSQL exposed — restrict access with pg_hba.conf"),
}

def scan_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def scan_ports(host: str, ports: dict) -> list:
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            if fut.result():
                open_ports.append({"port": port, "service": ports[port]})
    return sorted(open_ports, key=lambda x: x["port"])

# ─── HTTP Header Analyzer ────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security": (
        "HIGH", "Missing HSTS",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "content-security-policy": (
        "HIGH", "Missing CSP",
        "Define a Content-Security-Policy to prevent XSS attacks"
    ),
    "x-frame-options": (
        "MEDIUM", "Missing X-Frame-Options",
        "Add: X-Frame-Options: DENY to prevent clickjacking"
    ),
    "x-content-type-options": (
        "LOW", "Missing X-Content-Type-Options",
        "Add: X-Content-Type-Options: nosniff"
    ),
    "referrer-policy": (
        "LOW", "Missing Referrer-Policy",
        "Add: Referrer-Policy: strict-origin-when-cross-origin"
    ),
    "permissions-policy": (
        "LOW", "Missing Permissions-Policy",
        "Restrict browser features via Permissions-Policy header"
    ),
}

INFO_LEAKING_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                        "x-aspnetmvc-version", "x-generator"]

def fetch_headers(url: str) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScan/1.0"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            return dict(resp.headers)
    except Exception as e:
        return {"_error": str(e)}

def analyze_headers(headers: dict) -> list[Finding]:
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}

    for hdr, (sev, title, rec) in SECURITY_HEADERS.items():
        if hdr not in lower:
            findings.append(Finding(
                severity=sev, category="HTTP Headers",
                title=title,
                description=f"The response is missing the '{hdr}' security header.",
                recommendation=rec
            ))

    for hdr in INFO_LEAKING_HEADERS:
        if hdr in lower:
            findings.append(Finding(
                severity="INFO", category="Information Disclosure",
                title=f"Server version exposed via '{hdr}'",
                description=f"Header value: {lower[hdr]}",
                evidence=f"{hdr}: {lower[hdr]}",
                recommendation="Remove or obscure this header in server configuration"
            ))

    # Cookie flags
    cookies = lower.get("set-cookie", "")
    if cookies:
        if "httponly" not in cookies.lower():
            findings.append(Finding(
                severity="MEDIUM", category="Cookie Security",
                title="Cookie missing HttpOnly flag",
                description="Cookies without HttpOnly are accessible via JavaScript (XSS risk).",
                recommendation="Set HttpOnly flag on all sensitive cookies"
            ))
        if "secure" not in cookies.lower():
            findings.append(Finding(
                severity="MEDIUM", category="Cookie Security",
                title="Cookie missing Secure flag",
                description="Cookies without Secure may be sent over HTTP.",
                recommendation="Set Secure flag on all sensitive cookies"
            ))
        if "samesite" not in cookies.lower():
            findings.append(Finding(
                severity="LOW", category="Cookie Security",
                title="Cookie missing SameSite attribute",
                description="Missing SameSite may expose cookies to CSRF.",
                recommendation="Set SameSite=Strict or SameSite=Lax"
            ))

    return findings

# ─── TLS/SSL Checker ─────────────────────────────────────────────────────────

def check_tls(host: str, port: int = 443) -> tuple[dict, list[Finding]]:
    info = {}
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()

                info["protocol"] = proto
                info["cipher"] = cipher[0] if cipher else "unknown"
                info["bits"] = cipher[2] if cipher else 0

                # Expiry check
                exp_str = cert.get("notAfter", "")
                if exp_str:
                    exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.datetime.utcnow()).days
                    info["cert_expiry"] = exp_str
                    info["days_until_expiry"] = days_left
                    if days_left < 0:
                        findings.append(Finding("CRITICAL", "TLS/SSL",
                            "Certificate EXPIRED",
                            f"Certificate expired {abs(days_left)} days ago.",
                            recommendation="Renew certificate immediately"))
                    elif days_left < 30:
                        findings.append(Finding("HIGH", "TLS/SSL",
                            f"Certificate expiring in {days_left} days",
                            "Short certificate lifespan — renewal needed soon.",
                            recommendation="Renew certificate before expiry"))

                # Weak protocol
                if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append(Finding("HIGH", "TLS/SSL",
                        f"Weak TLS version: {proto}",
                        "Deprecated TLS versions are vulnerable to POODLE, BEAST.",
                        recommendation="Disable TLS 1.0/1.1; enforce TLS 1.2+"))

                # Weak cipher
                if cipher and ("RC4" in cipher[0] or "DES" in cipher[0] or "NULL" in cipher[0]):
                    findings.append(Finding("HIGH", "TLS/SSL",
                        f"Weak cipher: {cipher[0]}",
                        "Deprecated cipher suites provide weak encryption.",
                        recommendation="Configure server to use strong cipher suites only"))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding("HIGH", "TLS/SSL",
            "TLS Certificate validation failed",
            str(e), recommendation="Obtain a valid certificate from a trusted CA"))
        info["error"] = str(e)
    except Exception as e:
        info["error"] = str(e)

    return info, findings

# ─── Software Version Detector ───────────────────────────────────────────────

# Simplified CVE-style version advisories (educational approximations)
VERSION_ADVISORIES = [
    (r"Apache[/ ](\d+\.\d+\.\d+)", "Apache HTTP Server", "2.4.58",
     "Older Apache versions may be vulnerable to path traversal, mod_proxy issues"),
    (r"nginx[/ ](\d+\.\d+\.\d+)", "nginx", "1.25.3",
     "Older nginx versions may contain memory disclosure or HTTP/2 vulnerabilities"),
    (r"PHP[/ ](\d+\.\d+\.\d+)", "PHP", "8.2.0",
     "PHP versions before 8.1 are EOL and no longer receive security patches"),
    (r"OpenSSL[/ ](\d+\.\d+\.\d+)", "OpenSSL", "3.0.0",
     "OpenSSL < 3.0 may be vulnerable to various CVEs including Heartbleed-class bugs"),
    (r"WordPress[/ ](\d+\.\d+)", "WordPress", "6.4",
     "Outdated WordPress core is the #1 CMS attack vector"),
    (r"jQuery[/ v](\d+\.\d+\.\d+)", "jQuery", "3.7.0",
     "jQuery < 3.5 is vulnerable to XSS via HTML parsing (CVE-2020-11022/23)"),
]

def detect_versions(headers: dict, body: str = "") -> list[Finding]:
    findings = []
    combined = " ".join(list(headers.values()) + [body])

    for pattern, software, min_version, advisory in VERSION_ADVISORIES:
        match = re.search(pattern, combined, re.IGNORECASE)
        if match:
            detected = match.group(1)
            findings.append(Finding(
                severity="MEDIUM", category="Software Versioning",
                title=f"Detected {software} {detected}",
                description=advisory,
                evidence=f"Detected version: {detected} | Recommended minimum: {min_version}",
                recommendation=f"Update {software} to at least {min_version}"
            ))

    return findings

# ─── Common Path Checks ──────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    ("/.git/HEAD",        "HIGH",   "Git repository exposed",
     "Remove .git from web root or block access via server config"),
    ("/.env",             "CRITICAL","Environment file exposed",
     "Immediately remove .env from web root — contains secrets/credentials"),
    ("/wp-admin/",        "INFO",    "WordPress admin panel found",
     "Ensure admin login is rate-limited and uses 2FA"),
    ("/phpmyadmin/",      "HIGH",    "phpMyAdmin panel exposed",
     "Restrict phpMyAdmin to trusted IPs only"),
    ("/admin/",           "INFO",    "Admin panel found",
     "Ensure strong authentication is enforced"),
    ("/robots.txt",       "INFO",    "robots.txt accessible",
     "Review robots.txt — may reveal hidden endpoints"),
    ("/server-status",    "MEDIUM",  "Apache server-status exposed",
     "Restrict /server-status to internal IPs"),
    ("/actuator",         "HIGH",    "Spring Boot actuator exposed",
     "Restrict actuator endpoints — may expose env vars and heap dumps"),
    ("/.DS_Store",        "MEDIUM",  "macOS .DS_Store file exposed",
     "Block .DS_Store files via server config or .gitignore"),
]

def check_sensitive_paths(base_url: str) -> list[Finding]:
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for path, severity, title, rec in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VulnScan/1.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                if resp.status in (200, 301, 302, 403):
                    findings.append(Finding(
                        severity=severity, category="Exposed Resources",
                        title=title,
                        description=f"Path '{path}' returned HTTP {resp.status}",
                        evidence=f"URL: {url} → {resp.status}",
                        recommendation=rec
                    ))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                findings.append(Finding(
                    severity="INFO", category="Exposed Resources",
                    title=f"{title} (access restricted)",
                    description=f"Path '{path}' exists but access is forbidden (403)",
                    evidence=f"URL: {url} → 403",
                    recommendation=rec
                ))
        except Exception:
            pass

    return findings

# ─── Report Generator ─────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

def generate_report(result: ScanResult) -> str:
    lines = []
    sep = "═" * 60

    lines += [
        sep,
        "  🔍 VULNSCAN REPORT",
        sep,
        f"  Target     : {result.target}",
        f"  Scan Time  : {result.scan_time}",
        f"  Findings   : {len(result.findings)} total",
        sep, ""
    ]

    # Port summary
    lines.append("📡 OPEN PORTS")
    lines.append("─" * 40)
    if result.open_ports:
        for p in result.open_ports:
            tag = " ⚠️" if p["port"] in RISKY_PORTS else ""
            lines.append(f"  [{p['port']:>5}]  {p['service']}{tag}")
    else:
        lines.append("  No common ports open (or host unreachable)")
    lines.append("")

    # TLS summary
    if result.tls_info and "protocol" in result.tls_info:
        ti = result.tls_info
        lines.append("🔒 TLS/SSL INFO")
        lines.append("─" * 40)
        lines.append(f"  Protocol : {ti.get('protocol','?')}")
        lines.append(f"  Cipher   : {ti.get('cipher','?')} ({ti.get('bits','?')} bit)")
        if "cert_expiry" in ti:
            lines.append(f"  Expires  : {ti['cert_expiry']} ({ti.get('days_until_expiry','?')} days)")
        lines.append("")

    # Findings by severity
    lines.append("🚨 VULNERABILITY FINDINGS")
    lines.append("─" * 40)
    sorted_findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))

    if not sorted_findings:
        lines.append("  ✅ No vulnerabilities detected!")
    else:
        for i, f in enumerate(sorted_findings, 1):
            em = SEVERITY_EMOJI.get(f.severity, "❓")
            lines.append(f"\n  [{i:02d}] {em} [{f.severity}] {f.title}")
            lines.append(f"       Category : {f.category}")
            lines.append(f"       Detail   : {f.description}")
            if f.evidence:
                lines.append(f"       Evidence : {f.evidence}")
            lines.append(f"       Fix      : {f.recommendation}")

    # Severity summary
    lines += ["", sep, "  SUMMARY", "─" * 40]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sum(1 for f in result.findings if f.severity == sev)
        bar = "█" * count
        lines.append(f"  {SEVERITY_EMOJI[sev]} {sev:<10} {bar} {count}")

    lines += [sep,
              "  ⚠  For authorized use only. Always obtain permission before scanning.",
              sep]

    return "\n".join(lines)

# ─── Main ────────────────────────────────────────────────────────────────────

def run_scan(target: str) -> ScanResult:
    # Normalise target
    target = target.strip().rstrip("/")
    if not target.startswith("http"):
        base_url = f"https://{target}"
    else:
        base_url = target

    host = re.sub(r"^https?://", "", base_url).split("/")[0].split(":")[0]
    result = ScanResult(target=target,
                        scan_time=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    print(f"\n[*] Starting scan of: {target}")
    print(f"[*] Resolved host   : {host}\n")

    # 1. Port scan
    print("[*] Scanning common ports...")
    result.open_ports = scan_ports(host, COMMON_PORTS)
    print(f"    → {len(result.open_ports)} open port(s) found")

    for p in result.open_ports:
        if p["port"] in RISKY_PORTS:
            sev, desc = RISKY_PORTS[p["port"]]
            result.findings.append(Finding(
                severity=sev, category="Network Exposure",
                title=f"Risky port open: {p['port']}/{p['service']}",
                description=desc,
                evidence=f"Port {p['port']} ({p['service']}) is reachable",
                recommendation="Firewall this port or migrate to a safer alternative"
            ))

    # 2. HTTP headers
    print("[*] Fetching HTTP headers...")
    result.headers = fetch_headers(base_url)
    if "_error" not in result.headers:
        result.findings += analyze_headers(result.headers)
        result.findings += detect_versions(result.headers)
        print(f"    → {len(result.headers)} headers received")
    else:
        print(f"    → Error: {result.headers['_error']}")

    # 3. TLS check
    print("[*] Checking TLS/SSL configuration...")
    tls_info, tls_findings = check_tls(host)
    result.tls_info = tls_info
    result.findings += tls_findings
    if "protocol" in tls_info:
        print(f"    → {tls_info['protocol']} / {tls_info.get('cipher','?')}")
    else:
        print(f"    → {tls_info.get('error', 'TLS not available')}")

    # 4. Sensitive paths
    print("[*] Probing sensitive paths...")
    path_findings = check_sensitive_paths(base_url)
    result.findings += path_findings
    print(f"    → {len(path_findings)} interesting path(s) found")

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vuln_scanner.py <target>  [--json]")
        print("Examples:")
        print("  python vuln_scanner.py example.com")
        print("  python vuln_scanner.py https://example.com --json")
        sys.exit(1)

    target = sys.argv[1]
    as_json = "--json" in sys.argv

    result = run_scan(target)

    if as_json:
        data = asdict(result)
        data["findings"] = [asdict(f) for f in result.findings]
        print(json.dumps(data, indent=2))
    else:
        print("\n" + generate_report(result))
