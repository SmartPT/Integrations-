#!/usr/bin/env python3
import os
import re
import sys
import json
import csv
import urllib3
import requests
from datetime import datetime
from netmiko import ConnectHandler
 
# ─── CONFIG ─────────────────────────────────────────────────────────────────
WAZUH_URL   = os.getenv("WAZUH_URL", https://127.0.0.1:55000)
WAZUH_TOKEN = os.getenv("WAZUH_TOKEN", "")
VERIFY_TLS  = False
TIMEOUT     = 10
JSON_PATH   = "/var/ossec/logs/ransomware2.json"
 
CSV_MAC_TABLE = "/var/ossec/active-response/bin/cisco/mac_ports_with_switch.csv"  # UPDATE THIS PATH
 
USERNAME         = os.getenv("SWITCH_USER", "")
PASSWORD         = os.getenv("SWITCH_PASS", "")
ENABLE_PASSWORD  = os.getenv("SWITCH_ENABLE", "")
SSH_PORT         = 22
 
LOG_DIR = "/var/ossec/logs"
 
REGEX = {
    "agent_id": r'"agent":\s*{[^}]*?"id"\s*:\s*"([^"]+)"',
    "agent_ip": r'"agent":\s*{[^}]*?"ip"\s*:\s*"([^"]+)"',
    "agent_name": r'"agent":\s*{[^}]*?"name"\s*:\s*"([^"]+)"',
    "rule_id": r'"rule":\s*{[^}]*?"id"\s*:\s*"([^"]+)"',
}
 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
# ─── HELPERS ────────────────────────────────────────────────────────────────
 
def log(ip: str, text: str):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(f"{LOG_DIR}/{ip}.txt", "w") as f:
        f.write(text + "\n")
 
def debug(msg):
    print(f"[DEBUG] {msg}", file=sys.stderr)
 
def format_mac(mac: str):
    mac = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return f"{mac[:4]}.{mac[4:8]}.{mac[8:]}" if len(mac) == 12 else None
 
def read_json_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
 
def extract_data(text: str):
    def extract(key):
        match = re.search(REGEX[key], text, re.S)
        return match.group(1) if match else "N/A"
    return {
        "agent_id": extract("agent_id"),
        "agent_ip": extract("agent_ip"),
        "agent_name": extract("agent_name"),
        "rule_id": extract("rule_id"),
    }
 
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
 
def find_switch_by_mac(target_mac: str):
    target_mac = format_mac(target_mac)
    with open(CSV_MAC_TABLE, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            csv_mac = format_mac(row["MAC Address"])
            if csv_mac == target_mac:
                return row["Switch IP"], row["Port"]
    return None, None
 
def get_port_type(ssh, interface: str):
    out = ssh.send_command(f"show interface {interface} switchport")
    for line in out.splitlines():
        if "Operational Mode" in line:
            return line.split(":")[1].strip().lower()
    return None
 
def shutdown_port(ssh, interface: str):
    debug(f"Shutting down interface {interface}")
    ssh.enable()
    ssh.send_config_set([f"interface {interface}", "shutdown", "exit"])
 
def find_and_shutdown(ip: str, mac: str):
    formatted_mac = format_mac(mac)
    if not formatted_mac:
        debug(f"Invalid MAC format: {mac}")
        return None, None, "invalid_mac"
 
    switch_ip, port = find_switch_by_mac(formatted_mac)
    if not switch_ip or not port:
        debug(f"MAC {formatted_mac} not found in CSV table.")
        return None, None, "mac_not_in_csv"
 
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
        port_type = get_port_type(ssh, port)
        debug(f"Found MAC on {switch_ip} port {port}, type: {port_type}")
        if port_type and "access" in port_type:
            shutdown_port(ssh, port)
            log(ip, f"{switch_ip} {port} {ip}")
            ssh.disconnect()
            return switch_ip, port, "shutdown_success"
        ssh.disconnect()
        return switch_ip, port, "not_access_port"
    except Exception as e:
        debug(f"Failed on switch {switch_ip}: {e}")
        return switch_ip, port, "ssh_failed"
 
# ─── MAIN ───────────────────────────────────────────────────────────────────
 
def main():
    debug("Started Wazuh takedown script.")
    try:
        raw_json = read_json_text(JSON_PATH)
        debug("Loaded JSON file.")
    except FileNotFoundError:
        debug("JSON file not found.")
        sys.exit(1)
 
    data = extract_data(raw_json)
    agent_id = data["agent_id"]
    agent_ip = data["agent_ip"]
    agent_name = data["agent_name"]
    rule_id = data["rule_id"]
 
    debug(f"agent_id={agent_id}, agent_ip={agent_ip}, agent_name={agent_name}, rule_id={rule_id}")
 
    if agent_ip == "N/A" or agent_id == "N/A":
        debug("Missing agent ID or IP. Exiting.")
        sys.exit(2)
 
    debug("Requesting MAC from Wazuh API...")
    mac = get_mac_from_wazuh(agent_id, agent_ip)
 
    if not mac:
        debug("MAC not found via Wazuh.")
        status = "mac_not_found"
        port = "not_found"
        switch = "unknown"
        description = f"MAC not found in Wazuh for agent {agent_ip}"
    else:
        debug(f"MAC found: {mac}")
        switch, port, status = find_and_shutdown(agent_ip, mac)
        if status == "shutdown_success":
            description = f"Port {port} on switch {switch} was shut down due to alert from agent {agent_ip}"
        elif status == "not_access_port":
            description = f"MAC {mac} found, but port {port} is not access"
        elif status == "mac_not_in_csv":
            description = f"MAC {mac} not found in MAC table CSV"
        else:
            description = f"No access port shutdown for MAC {mac} (agent {agent_ip})"
            switch = switch or "unknown"
            port = port or "not_found"
 
    message = (
        f"Rule ID: {rule_id} "
        f"*Agent Name*: {agent_name} (IP: {agent_ip}) "
        f"*Description*: {description}; "
        "Please review the activity related to this event."
    )
 
    output_data = {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "rule_id": rule_id,
        "description": description,
        "mac": format_mac(mac) if mac else "unknown",
        "ip": agent_ip,
        "port": port,
        "switch": switch,
        "status": status,
        "message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
 
    print(json.dumps(output_data, ensure_ascii=False))
    debug("✅ JSON output sent to stdout")
 
if __name__ == "__main__":
    main()
