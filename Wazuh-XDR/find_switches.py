#!/usr/bin/env python3
"""
Ping sweep multiple IP ranges (CIDR or range) and save reachable IPs to switches.txt
"""
 
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from typing import List, Union
 
# ─── CONFIG ────────────────────────────────────────────────────────────────
IP_RANGES = [
    "192.168.0.12",
    "10.1.5.6"
]
OUTPUT_FILE = "switches.txt"
MAX_WORKERS = 100
PING_COUNT = 1
PING_TIMEOUT = 1  # seconds
# ───────────────────────────────────────────────────────────────────────────
 
IS_WINDOWS = platform.system().lower() == "windows"
 
def expand_range(entry: str) -> List[str]:
    hosts = []
    entry = entry.strip()
    if "/" in entry:
        # CIDR subnet
        net = ipaddress.ip_network(entry, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    elif "-" in entry:
        # Start-End IP
        start_ip, end = entry.split("-")
        start = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end) if "." in end else ipaddress.IPv4Address(".".join(start_ip.split(".")[:-1]) + f".{end}")
        hosts = [str(ip) for ip in ipaddress.summarize_address_range(start, end_ip)][0].hosts()
    else:
        # Single IP
        hosts = [entry]
    return list(map(str, hosts))
 
def ping_host(ip: str) -> Union[str, None]:
    cmd = ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT), ip] if not IS_WINDOWS else ["ping", "-n", "1", "-w", "1000", ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return ip
    except subprocess.CalledProcessError:
        return None
 
def ping_sweep(ip_ranges: List[str]) -> List[str]:
    print("🔍 Starting ping sweep...")
    all_hosts = []
    for entry in ip_ranges:
        all_hosts.extend(expand_range(entry))
 
    live_hosts = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for result in executor.map(ping_host, all_hosts):
            if result:
                print(f"✅ Alive: {result}")
                live_hosts.append(result)
 
    return sorted(set(live_hosts))
 
def write_to_file(hosts: List[str], filename: str):
    with open(filename, "w") as f:
        for host in hosts:
            f.write(f"{host}\n")
    print(f"📄 {len(hosts)} live hosts written to {filename}")
 
def main():
    live_ips = ping_sweep(IP_RANGES)
    write_to_file(live_ips, OUTPUT_FILE)
 
if __name__ == "__main__":
    main()
