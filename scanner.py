import nmap
import requests
import socket
import ipaddress


def _allowed_scope(value: str, is_network: bool = False) -> bool:
    """Limit live scanning to localhost/private IPv4 lab ranges."""
    try:
        parsed = ipaddress.ip_network(value.strip(), strict=False) if is_network else ipaddress.ip_address(value.strip())
        if parsed.version != 4 or not (parsed.is_private or parsed.is_loopback):
            return False
        if is_network and parsed.num_addresses > 256:
            return False
        return True
    except ValueError:
        return False


def _scope_warning(value: str, is_network: bool = False) -> bool:
    if not _allowed_scope(value, is_network):
        print("[-] Target blocked. Use only authorized localhost/private IPv4 lab targets; discovery is limited to 256 addresses.")
        return False
    return True

def section(title: str):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

def subline():
    print("-" * 70)

def kv(key: str, value: str):
    print(f"{key:<14}: {value}")

def print_table(headers, rows):
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(header_line)
    subline()
    for row in rows:
        print("  ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)))


def discover_hosts(network: str):
    """
    Discover live hosts in a given CIDR network (e.g., 192.168.56.0/24).
    Returns a list of IPs.
    """
    if not _scope_warning(network, is_network=True):
        return []
    section("HOST DISCOVERY")
    kv("Network", network)
    subline()

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments="-sn -T4 -n")
    except Exception as e:
        print(f"[-] Discovery error: {e}")
        return []

    hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            hosts.append(host)

    if not hosts:
        print("[-] No live hosts detected.")
        return []

    rows = [[str(i), h, "UP"] for i, h in enumerate(hosts, start=1)]
    print_table(["#", "HOST", "STATE"], rows)
    return hosts


def network_scan(target: str):
    if not _scope_warning(target):
        return
    section("NETWORK SCAN RESULTS")
    kv("Target", target)
    subline()

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-sn -T4 -n")
    except Exception as e:
        print(f"[-] Scan error: {e}")
        return

    hosts_up = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            hosts_up.append(host)

    if not hosts_up:
        print("[-] No active hosts found.")
        return

    rows = [[h, "UP"] for h in hosts_up]
    print_table(["HOST", "STATE"], rows)
    subline()
    print(f"[+] Total hosts up: {len(hosts_up)}")


def port_scan(target: str):
    if not _scope_warning(target):
        return
    section("OPEN PORTS (FAST SCAN)")
    kv("Target", target)
    subline()

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-T4 -F --open -Pn -n")
    except Exception as e:
        print(f"[-] Scan error: {e}")
        return

    if not nm.all_hosts():
        print("[-] Host seems down or not reachable.")
        return

    rows = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                state = nm[host][proto][port].get("state", "")
                service = nm[host][proto][port].get("name", "unknown")
                rows.append([host, f"{port}/{proto}", service, state])

    if not rows:
        print("[+] No open ports found (within fast scan range).")
        return

    print_table(["HOST", "PORT", "SERVICE", "STATE"], rows)
    subline()
    print(f"[+] Total open ports found: {len(rows)}")


def cve_lookup(service: str, version: str, limit: int = 2):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": f"{service} {version}",
        "resultsPerPage": limit
    }

    try:
        r = requests.get(url, params=params, timeout=10)
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        results = []
        for v in vulns:
            cve_id = v["cve"]["id"]
            desc = v["cve"]["descriptions"][0]["value"]
            results.append({"cve": cve_id, "desc": desc})
        return results
    except Exception:
        return []


def service_detection(target: str, do_cve: bool = True):
    if not _scope_warning(target):
        return
    section("SERVICE & VERSION DETECTION")
    kv("Target", target)
    kv("CVE Lookup", "ON" if do_cve else "OFF")
    subline()

    nm = nmap.PortScanner()
    try:
        nm.scan(
            hosts=target,
            arguments="-sV --version-light -T4 -Pn -n -p 21,22,23,25,53,80,110,139,143,443,445,3389,3306"
        )
    except Exception as e:
        print(f"[-] Scan error: {e}")
        return

    if not nm.all_hosts():
        print("[-] Host seems down or not reachable.")
        return

    rows = []
    cve_rows = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                state = nm[host][proto][port].get("state", "")
                service = nm[host][proto][port].get("name", "unknown")
                product = nm[host][proto][port].get("product", "")
                version = nm[host][proto][port].get("version", "")
                extra = nm[host][proto][port].get("extrainfo", "")

                version_str = (product + " " + version).strip()
                if extra and len(version_str) < 30:
                    version_str = (version_str + f" ({extra})").strip()

                rows.append([host, f"{port}/{proto}", service, state, version_str])

                if do_cve and service != "unknown" and version:
                    cves = cve_lookup(service, version, limit=2)
                    for c in cves:
                        cve_rows.append([host, f"{port}/{proto}", service, c["cve"], c["desc"][:120] + "..."])

    if rows:
        print_table(["HOST", "PORT", "SERVICE", "STATE", "VERSION/INFO"], rows)
    else:
        print("[-] No services detected.")

    if do_cve:
        section("CVE RESULTS (TOP MATCHES)")
        if cve_rows:
            print_table(["HOST", "PORT", "SERVICE", "CVE", "DESCRIPTION"], cve_rows)
        else:
            print("[+] No CVEs returned for detected services (or versions not available).")


def brute_force_risk_analyzer(target: str):
    if not _scope_warning(target):
        return
    section("BRUTE-FORCE RISK ANALYZER")
    kv("Target", target)
    kv("Mode", "Simulation only (no attack executed)")
    subline()

    risky_ports = {
        21: ("FTP", "High", "Often clear-text credentials unless FTPS/SFTP"),
        22: ("SSH", "Medium", "Common target if password auth is enabled"),
        23: ("Telnet", "High", "Insecure clear-text authentication"),
        3389: ("RDP", "Medium", "Common brute-force target when exposed"),
        445: ("SMB", "Medium", "Credential abuse / misconfiguration risk"),
    }

    rows = []
    for port, (svc, risk, reason) in risky_ports.items():
        try:
            s = socket.socket()
            s.settimeout(2)
            is_open = (s.connect_ex((target, port)) == 0)
            s.close()
            if is_open:
                rows.append([f"{port}/tcp", svc, "OPEN", risk, reason])
        except Exception:
            continue

    if not rows:
        print("[+] No common authentication services detected as OPEN on this target.")
        print("[+] This typically indicates a hardened or inactive host (good security posture).")
        return

    print_table(["PORT", "SERVICE", "STATE", "RISK", "WHY IT MATTERS"], rows)
    subline()
    print("Mitigation Recommendations:")
    print("- Enforce strong passwords or keys-only authentication (for SSH).")
    print("- Enable rate-limiting / lockout policies, and monitoring.")
    print("- Restrict exposure to internal lab networks (Host-Only) or VPN.")


def calculate_risk_score(target: str):
    if not _scope_warning(target):
        return
    section("FINAL RISK ASSESSMENT (SCORE 0–10)")
    kv("Target", target)
    subline()

    score = 0
    reasons = set()

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-T4 -F -Pn -n -sV --version-light")
    except Exception as e:
        print(f"[-] Scan error: {e}")
        return

    if not nm.all_hosts():
        print("[-] Host seems down or not reachable.")
        return

    cve_hit = False
    open_services = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                state = nm[host][proto][port].get("state", "")
                if state != "open":
                    continue

                service = nm[host][proto][port].get("name", "unknown")
                product = nm[host][proto][port].get("product", "")
                version = nm[host][proto][port].get("version", "")

                open_services.append((port, proto, service, product, version))

                if service in ("ftp", "telnet"):
                    score += 3
                    reasons.add(f"{service.upper()} exposed (+3)")
                elif service in ("ssh", "rdp", "smb", "microsoft-ds", "netbios-ssn"):
                    score += 2
                    reasons.add("Auth service exposed (SSH/RDP/SMB) (+2)")
                elif service in ("http",):
                    score += 2
                    reasons.add("HTTP service exposed (+2)")

                if (not cve_hit) and service != "unknown" and version:
                    cves = cve_lookup(service, version, limit=1)
                    if cves:
                        cve_hit = True
                        score += 3
                        reasons.add("CVE match found for a detected version (+3)")

    if score > 10:
        score = 10

    if score <= 3:
        level = "LOW"
    elif score <= 6:
        level = "MEDIUM"
    else:
        level = "HIGH"

    rows = []
    for (port, proto, svc, prod, ver) in open_services:
        vstr = (prod + " " + ver).strip()
        rows.append([f"{port}/{proto}", svc, vstr])

    if rows:
        print("Open services observed:")
        print_table(["PORT", "SERVICE", "VERSION/INFO"], rows)
        subline()

    print(f"Risk Score : {score} / 10")
    print(f"Risk Level : {level}")
    print("\nContributing factors:")
    if reasons:
        for r in sorted(reasons):
            print(f"- {r}")
    else:
        print("- No significant exposure detected in fast scan.")

    subline()
    print("Recommended next actions:")
    print("- Disable unnecessary services and close unused ports.")
    print("- Apply updates/patches for detected software versions.")
    print("- Restrict access (firewall / host-only segmentation) and monitor logs.")
