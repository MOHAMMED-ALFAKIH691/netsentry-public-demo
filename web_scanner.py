"""Safe, structured scanner functions for the local web dashboard.

Only IPv4 loopback and RFC1918 private address space are accepted. Network
 discovery is limited to 256 addresses. This is intended for authorized labs.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
COMMON_PORTS = "21,22,23,25,53,80,110,139,143,443,445,3389,3306,5432,8080,8443"
RISKY_PORTS = {
    21: ("FTP", "HIGH", "FTP may expose credentials if encryption is not configured."),
    22: ("SSH", "MEDIUM", "SSH should use strong keys, restricted access, and rate limiting."),
    23: ("Telnet", "HIGH", "Telnet transmits data, including credentials, without encryption."),
    445: ("SMB", "MEDIUM", "SMB should be restricted to trusted networks and hardened."),
    3389: ("RDP", "MEDIUM", "Remote Desktop should be restricted and protected with MFA/VPN."),
}


class ScanError(ValueError):
    pass


def validate_ip_target(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ScanError("Enter one valid IPv4 address, not a hostname or URL.") from exc
    if addr.version != 4:
        raise ScanError("Only IPv4 targets are supported in this version.")
    if not (addr.is_private or addr.is_loopback):
        raise ScanError("Target blocked: only localhost or private IPv4 lab addresses are allowed.")
    return str(addr)


def validate_network(value: str) -> str:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ScanError("Enter a valid IPv4 network in CIDR format, such as 192.168.56.0/24.") from exc
    if net.version != 4:
        raise ScanError("Only IPv4 networks are supported in this version.")
    if not (net.is_private or net.is_loopback):
        raise ScanError("Network blocked: host discovery is limited to private or loopback networks.")
    if net.num_addresses > 256:
        raise ScanError("Network too large. The maximum discovery range is 256 addresses (/24).")
    return str(net)


def _require_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        raise ScanError("Nmap is not installed. On Kali run: sudo apt update && sudo apt install -y nmap")
    return path


def _run_nmap(target: str, args: list[str], timeout: int = 90) -> ET.Element:
    nmap = _require_nmap()
    command = [nmap, "-oX", "-", "-n", "-T3", "--max-retries", "2", "--host-timeout", "75s", *args, target]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScanError("The scan timed out. Try one host or a smaller lab network.") from exc
    if not proc.stdout.strip():
        message = (proc.stderr or "Nmap returned no scan output.").strip()
        raise ScanError(message[:500])
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError as exc:
        message = (proc.stderr or "Could not parse Nmap output.").strip()
        raise ScanError(message[:500]) from exc
    if proc.returncode not in (0, 1) and not root.findall("host"):
        raise ScanError((proc.stderr or "Nmap scan failed.").strip()[:500])
    return root


def _parse_hosts(root: ET.Element) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"
        address = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                address = addr.get("addr", "")
                break
        if not address:
            continue
        ports: list[dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                ports.append({
                    "port": int(port_el.get("portid", "0")),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
                    "service": service_el.get("name", "unknown") if service_el is not None else "unknown",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                    "extra": service_el.get("extrainfo", "") if service_el is not None else "",
                })
        hosts.append({"ip": address, "status": status, "ports": ports})
    return hosts


def discover_hosts(network: str) -> dict[str, Any]:
    net = validate_network(network)
    root = _run_nmap(net, ["-sn"], timeout=120)
    hosts = _parse_hosts(root)
    live = [{"ip": h["ip"], "status": h["status"]} for h in hosts if h["status"] == "up"]
    return {"network": net, "hosts": live, "count": len(live), "generated_at": _timestamp()}


def scan_target(target: str, include_cve: bool = True) -> dict[str, Any]:
    ip = validate_ip_target(target)
    root = _run_nmap(ip, ["-sV", "--version-light", "-F", "-Pn", "--reason"], timeout=100)
    hosts = _parse_hosts(root)
    host_data = next((h for h in hosts if h["ip"] == ip), None)
    if not host_data:
        raise ScanError("Nmap did not return a result for this target. Check that the lab machine is running and reachable.")

    open_ports = [p for p in host_data["ports"] if p["state"] == "open"]
    cves: list[dict[str, Any]] = []
    cve_status = "Not requested"
    if include_cve:
        cves, cve_status = lookup_cves(open_ports)

    risk_items = []
    score = 0
    for port in open_ports:
        pnum = port["port"]
        if pnum in RISKY_PORTS:
            service, level, reason = RISKY_PORTS[pnum]
            risk_items.append({"port": pnum, "service": service, "level": level, "reason": reason})
            score += {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[level]
        elif pnum in (3306, 5432, 1433, 27017):
            risk_items.append({"port": pnum, "service": port["service"].upper(), "level": "MEDIUM", "reason": "A database service is exposed; restrict it to trusted application hosts."})
            score += 2
        elif pnum in (80, 8080):
            risk_items.append({"port": pnum, "service": port["service"].upper(), "level": "LOW", "reason": "Review the web service configuration, patch level, and HTTPS deployment."})
            score += 1
    score = min(score, 10)
    # Overall category follows the highest individual exposure factor so a
    # MEDIUM/HIGH finding is not hidden by a low aggregate numeric score.
    factor_levels = {item["level"] for item in risk_items}
    level = "HIGH" if "HIGH" in factor_levels else "MEDIUM" if "MEDIUM" in factor_levels else "LOW"

    recommendations = _recommendations(open_ports)
    simulation = {
        "mode": "Exposure simulation only",
        "executed": False,
        "items": [
            {"port": p["port"], "service": p["service"], "risk": RISKY_PORTS[p["port"]][1], "result": "Authentication service exposed; no login attempt was made."}
            for p in open_ports if p["port"] in RISKY_PORTS
        ],
    }
    return {
        "target": ip,
        "generated_at": _timestamp(),
        "host_status": host_data["status"],
        "open_ports": open_ports,
        "open_port_count": len(open_ports),
        "risk_score": score,
        "risk_level": level,
        "risk_items": risk_items,
        "simulation": simulation,
        "cves": cves,
        "cve_status": cve_status,
        "recommendations": recommendations,
        "scope_notice": "Authorized private/loopback lab scan. No exploitation or password guessing is performed.",
    }


def lookup_cves(open_ports: list[dict[str, Any]], max_queries: int = 4) -> tuple[list[dict[str, Any]], str]:
    candidates = []
    for port in open_ports:
        product = (port.get("product") or "").strip()
        version = (port.get("version") or "").strip()
        service = (port.get("service") or "").strip()
        if product and version:
            candidates.append((product, version, service, port["port"]))
    if not candidates:
        return [], "No product/version strings were detected; CVE lookup was skipped."

    results: list[dict[str, Any]] = []
    checked = 0
    try:
        for product, version, service, port in candidates[:max_queries]:
            response = requests.get(
                NVD_URL,
                params={"keywordSearch": f"{product} {version}", "resultsPerPage": 3},
                timeout=8,
                headers={"User-Agent": "Network-Pentest-Tool-Educational/1.0"},
            )
            response.raise_for_status()
            payload = response.json()
            checked += 1
            for item in payload.get("vulnerabilities", []):
                cve = item.get("cve", {})
                descriptions = cve.get("descriptions", [])
                description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
                score = None
                metrics = cve.get("metrics", {})
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(metric_key, [])
                    if entries:
                        score = entries[0].get("cvssData", {}).get("baseScore")
                        if score is not None:
                            break
                results.append({
                    "id": cve.get("id", "Unknown"),
                    "description": description[:500],
                    "cvss": score,
                    "product_query": f"{product} {version}",
                    "port": port,
                    "match_type": "Keyword match — verify affected version/configuration manually",
                })
    except requests.RequestException:
        return results, "NVD could not be reached. Check Internet access and try again."
    except (ValueError, KeyError, TypeError):
        return results, "NVD returned an unexpected response; CVE results may be incomplete."
    # Deduplicate by CVE ID, preserving first match.
    unique = {}
    for item in results:
        unique.setdefault(item["id"], item)
    return list(unique.values())[:8], f"NVD keyword lookup completed ({checked} product/version queries). Matches are not proof of exploitability."


def _recommendations(open_ports: list[dict[str, Any]]) -> list[str]:
    ports = {p["port"] for p in open_ports}
    recs = []
    if 23 in ports:
        recs.append("Disable Telnet and use SSH instead; Telnet does not encrypt credentials.")
    if 21 in ports:
        recs.append("Disable FTP if unnecessary or replace it with a securely configured encrypted transfer method.")
    if 22 in ports:
        recs.append("Restrict SSH to trusted IPs, prefer key-based authentication, and enable rate limiting.")
    if 445 in ports:
        recs.append("Restrict SMB to trusted lab hosts and review share permissions and patch status.")
    if 3389 in ports:
        recs.append("Do not expose RDP broadly; require VPN, MFA, and account lockout protections.")
    if ports.intersection({3306, 5432, 1433, 27017}):
        recs.append("Bind database services to trusted interfaces and firewall them from untrusted clients.")
    if ports.intersection({80, 8080}):
        recs.append("Review web server updates, security headers, and whether HTTPS should be enabled.")
    if not recs:
        recs.append("No common high-risk services were identified in the selected fast-scan range; this is not a guarantee of security.")
    recs.append("Verify software versions against vendor advisories before concluding that a vulnerability applies.")
    return recs


def _timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def demo_assessment() -> dict[str, Any]:
    """Clearly synthetic, read-only example data; performs no network activity."""
    ports = [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.2p1", "extra": ""},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "Apache httpd", "version": "2.4.57", "extra": ""},
    ]
    return {
        "target": "192.168.56.10 (SIMULATED)",
        "generated_at": _timestamp(),
        "host_status": "up (simulated)",
        "open_ports": ports,
        "open_port_count": len(ports),
        "risk_score": 2,
        "risk_level": "MEDIUM",
        "risk_items": [
            {"port": 22, "service": "SSH", "level": "MEDIUM", "reason": "SSH should use strong keys, restricted access, and rate limiting."},
            {"port": 80, "service": "HTTP", "level": "LOW", "reason": "Review the web service configuration, patch level, and HTTPS deployment."},
        ],
        "simulation": {"mode": "Exposure simulation only", "executed": False, "items": [{"port": 22, "service": "ssh", "risk": "MEDIUM", "result": "Example only: authentication service exposed; no login attempt was made."}]},
        "cves": [],
        "cve_status": "Demo dataset: no live NVD lookup was performed.",
        "recommendations": [
            "Restrict SSH to trusted IPs, prefer key-based authentication, and enable rate limiting.",
            "Review web server updates, security headers, and whether HTTPS should be enabled.",
            "Verify software versions against vendor advisories before concluding that a vulnerability applies.",
        ],
        "scope_notice": "SIMULATED DATA ONLY — no device was scanned and no network traffic was sent.",
        "demo": True,
    }
