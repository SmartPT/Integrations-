#!/usr/bin/env python3
"""
Connects to switches via SSH, fetches MAC addresses and access ports,
and saves the results in a CSV file (MAC Address, Port, Switch IP).
"""
 
import paramiko
import csv
import re
from pathlib import Path
import os
 
# ─── CONFIG ────────────────────────────────────────────────────────────────
SWITCH_LIST = "switches.txt"   # File with one IP per line
SSH_USER = os.getenv("SSH_USER", "")
SSH_PASS = os.getenv("SSH_PASS", "")
SSH_PORT = 22
OUTPUT_CSV = "mac_ports_with_switch.csv"
SHOW_MAC_CMD = "show mac address-table"  # Change if needed per switch brand
# ───────────────────────────────────────────────────────────────────────────
 
def read_switch_list(file_path: str):
    return [line.strip() for line in Path(file_path).read_text().splitlines() if line.strip()]
 
def ssh_run_command(host: str, command: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username=SSH_USER, password=SSH_PASS, port=SSH_PORT, timeout=10)
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode()
    finally:
        client.close()
 
def parse_mac_output(output: str, switch_ip: str):
    """
    Parses Cisco-style output like:
    VLAN   MAC Address       Type       Ports
    ----   -----------       --------   -----
    1      0011.2233.4455    DYNAMIC    Gi1/0/1
    """
    results = []
    for line in output.splitlines():
        match = re.search(r"([0-9a-fA-F.:]{12,})\s+\S+\s+([A-Za-z0-9/]+)", line)
        if match:
            mac = match.group(1)
            port = match.group(2)
            results.append((mac, port, switch_ip))
    return results
 
def collect_mac_port_data(switch_ips: list[str]) -> list[tuple[str, str, str]]:
    all_data = []
    for ip in switch_ips:
        print(f"🔌 Connecting to {ip}")
        try:
            output = ssh_run_command(ip, SHOW_MAC_CMD)
            mac_port_switch = parse_mac_output(output, ip)
            all_data.extend(mac_port_switch)
        except Exception as e:
            print(f"❌ Failed to connect to {ip}: {e}")
    return all_data
 
def save_to_csv(data: list[tuple[str, str, str]], filename: str):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["MAC Address", "Port", "Switch IP"])
        writer.writerows(data)
 
def main():
    switch_ips = read_switch_list(SWITCH_LIST)
    data = collect_mac_port_data(switch_ips)
    save_to_csv(data, OUTPUT_CSV)
    print(f"✅ MAC list saved to: {OUTPUT_CSV}")
 
if __name__ == "__main__":
    main()
