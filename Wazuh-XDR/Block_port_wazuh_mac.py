#!/usr/bin/env python3
"""
block_from_json.py

• קורא את /var/ossec/logs/extracted_data.json
• מחלץ agent_id ו-agent_ip בעזרת regex
• משיג MAC דרך Wazuh API
• מכבה את הפורט בסוויץ' אם מדובר בפורט גישה (access)

תלויות: requests, netmiko
"""

import os
import re
import sys
import urllib3
import requests
from netmiko import ConnectHandler

# ─── CONFIG ─────────────────────────────────────────────────────────────────
WAZUH_URL   = os.getenv("WAZUH_URL", "https://127.0.0.1:55000")
WAZUH_TOKEN = os.getenv("WAZUH_TOKEN", "eyJ...")  # ← הכנס כאן או במשתנה סביבה
VERIFY_TLS  = False
TIMEOUT     = 10
JSON_PATH   = "/var/ossec/logs/extracted_data.json"

SWITCH_IPS       = ["192.168.1.1"]
USERNAME         = "your_user"
PASSWORD         = "your_pass"
ENABLE_PASSWORD  = "your_enable_pass"
SSH_PORT         = 22

LOG_DIR = "/var/ossec/logs"
REGEX = {
    "agent_id": r'"agent":\s*{[^}]*?"id"\s*:\s*"([^"]+)"',
    "agent_ip": r'"agent":\s*{[^}]*?"ip"\s*:\s*"([^"]+)"',
}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ────────────────────────────────────────────────────────────────────────────

def log(ip: str, text: str):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(f"{LOG_DIR}/{ip}.txt", "a") as f:
        f.write(text + "\n")

def format_mac(mac: str):
    mac = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return f"{mac[:4]}.{mac[4:8]}.{mac[8:]}" if len(mac) == 12 else None

def read_json_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def extract_id_ip(text: str) -> tuple[str, str]:
    id_match = re.search(REGEX["agent_id"], text, re.S)
    ip_match = re.search(REGEX["agent_ip"], text, re.S)
    if not (id_match and ip_match):
        print("❌ agent_id or agent_ip not found in JSON", file=sys.stderr)
        sys.exit(2)
    return id_match.group(1), ip_match.group(1)

def api_get(endpoint: str) -> dict:
    r = requests.get(
        f"{WAZUH_URL}{endpoint}",
        headers={"Authorization": f"Bearer {WAZUH_TOKEN}"},
        verify=VERIFY_TLS,
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()

def get_mac_from_wazuh(agent_id: str, ip: str):
    netaddr = api_get(f"/syscollector/{agent_id}/netaddr")
    iface = next(
        (i["iface"] for i in netaddr["data"]["affected_items"]
         if i.get("proto") == "ipv4" and i.get("address") == ip),
        None,
    )
    if not iface:
        return None
    netiface = api_get(f"/syscollector/{agent_id}/netiface")
    return next(
        (i["mac"] for i in netiface["data"]["affected_items"]
         if i["name"] == iface),
        None,
    )

def get_ports(mac: str, mac_table: str):
    return [line.split()[-1] for line in mac_table.splitlines() if mac in line.lower()]

def get_port_type(ssh, interface: str):
    out = ssh.send_command(f"show interface {interface} switchport")
    for line in out.splitlines():
        if "Operational Mode" in line:
            return line.split(":")[1].strip().lower()
    return None

def shutdown_port(ssh, interface: str):
    ssh.enable()
    ssh.send_config_set([f"interface {interface}", "shutdown", "exit"])

def find_and_shutdown(ip: str, mac: str):
    formatted_mac = format_mac(mac)
    if not formatted_mac:
        log(ip, f"❌ Invalid MAC format: {mac}")
        return

    log(ip, f"🧬 MAC (formatted): {formatted_mac}")

    for switch_ip in SWITCH_IPS:
        try:
            ssh = ConnectHandler(
                device_type="cisco_ios",
                host=switch_ip,
                username=USERNAME,
                password=PASSWORD,
                secret=ENABLE_PASSWORD,
                port=SSH_PORT,
            )
            ssh.enable()
            mac_table = ssh.send_command("show mac address-table")
            ports = get_ports(formatted_mac, mac_table)

            for port in ports:
                if get_port_type(ssh, port) == "access":
                    shutdown_port(ssh, port)
                    log(ip, f"✅ Shut down port {port} on switch {switch_ip}")
                    ssh.disconnect()
                    return

            ssh.disconnect()
        except Exception as e:
            log(ip, f"❌ Failed on switch {switch_ip}: {e}")

    log(ip, f"❌ MAC {formatted_mac} not found on any switch")

# ─── MAIN ───────────────────────────────────────────────────────────────────
def main():
    raw_json = read_json_text(JSON_PATH)
    agent_id, agent_ip = extract_id_ip(raw_json)

    log(agent_ip, f"🔍 Looking for MAC via Wazuh (agent {agent_id})")
    mac = get_mac_from_wazuh(agent_id, agent_ip)

    if not mac:
        log(agent_ip, "❌ MAC not found in Wazuh")
        sys.exit(1)

    log(agent_ip, f"🧭 Found MAC: {mac}")
    find_and_shutdown(agent_ip, mac)

if __name__ == "__main__":
    main()
