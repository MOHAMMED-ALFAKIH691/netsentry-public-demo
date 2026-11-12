import sys
from datetime import datetime
from contextlib import contextmanager

from scanner import (
    discover_hosts,
    network_scan,
    port_scan,
    service_detection,
    brute_force_risk_analyzer,
    calculate_risk_score
)

class Tee:
    """Write to console + file at the same time."""
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)

    def flush(self):
        for s in self.streams:
            s.flush()

@contextmanager
def tee_stdout_to_file(filepath: str):
    original = sys.stdout
    f = open(filepath, "w", encoding="utf-8")
    sys.stdout = Tee(original, f)
    try:
        yield
    finally:
        sys.stdout = original
        f.close()

def banner():
    print("=" * 70)
    print("   Network Penetration Testing Tool")
    print("   CLI Version - Educational Use Only")
    print("=" * 70)

def menu():
    print("\n[0] Discover hosts & Select target")
    print("[1] Network Scan (on selected target)")
    print("[2] Port Scan (Fast)")
    print("[3] Service Detection + CVE")
    print("[4] Brute-Force Risk Analyzer (Simulation)")
    print("[5] Overall Risk Score (0–10)")
    print("[6] Generate Full Report (TXT)")
    print("[7] Exit")

def generate_full_report(target: str):
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename = f"report_{ts}.txt"

    with tee_stdout_to_file(filename):
        print("=" * 70)
        print("PROJECT REPORT (AUTO-GENERATED)")
        print("=" * 70)
        print(f"Target       : {target}")
        print(f"Generated at : {datetime.now().isoformat(sep=' ', timespec='seconds')}")
        print("=" * 70)

        port_scan(target)
        service_detection(target, do_cve=True)
        brute_force_risk_analyzer(target)
        calculate_risk_score(target)

        print("\n" + "=" * 70)
        print("END OF REPORT")
        print("=" * 70)

    print(f"\n[+] Report saved successfully: {filename}")

def main():
    banner()

    network = input("\nEnter local network (CIDR) for discovery (e.g., 192.168.56.0/24): ").strip()
    target = None
    last_hosts = []

    while True:
        menu()
        choice = input("\nSelect an option: ").strip()

        if choice == "0":
            last_hosts = discover_hosts(network)
            if last_hosts:
                try:
                    sel = int(input("\nSelect target number: ").strip())
                    if 1 <= sel <= len(last_hosts):
                        target = last_hosts[sel - 1]
                        print(f"\n[+] Target selected: {target}")
                    else:
                        print("[-] Invalid selection.")
                except ValueError:
                    print("[-] Please enter a valid number.")

        elif choice == "1":
            if target:
                network_scan(target)
            else:
                print("[-] Please select a target first (option 0).")

        elif choice == "2":
            if target:
                port_scan(target)
            else:
                print("[-] Please select a target first (option 0).")

        elif choice == "3":
            if target:
                service_detection(target, do_cve=True)
            else:
                print("[-] Please select a target first (option 0).")

        elif choice == "4":
            if target:
                brute_force_risk_analyzer(target)
            else:
                print("[-] Please select a target first (option 0).")

        elif choice == "5":
            if target:
                calculate_risk_score(target)
            else:
                print("[-] Please select a target first (option 0).")

        elif choice == "6":
            if target:
                generate_full_report(target)
            else:
                print("[-] Please select a target first (option 0).")

        elif choice == "7":
            print("\nExiting...")
            break

        else:
            print("[-] Invalid option, try again.")

if __name__ == "__main__":
    main()
