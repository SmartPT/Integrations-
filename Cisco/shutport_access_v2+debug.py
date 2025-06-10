import re
import subprocess
import sys
import json
from datetime import datetime
from netmiko import ConnectHandler

# --- CONFIGURATION ---
SWITCH_IPS = [
    # לדוגמה: "192.168.1.1"
 
]

USERNAME = "admin"
PASSWORD = "!"
SSH_PORT = 22
ENABLE_PASSWORD = ""

def debug(msg):
    print(f"[DEBUG] {msg}", file=sys.stderr)

def format_mac_for_cisco(mac):
    mac = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    if len(mac) != 12:
        raise ValueError("Invalid MAC address length")
    return f"{mac[:4]}.{mac[4:8]}.{mac[8:]}"


def get_ports_from_mac(mac, mac_table_output):
    ports = []
    for line in mac_table_output.splitlines():
        if mac.lower() in line.lower():
            parts = line.split()
            if len(parts) >= 4:
                ports.append(parts[-1])
    return ports


def get_port_type(ssh, interface):
    cmd = f"show interface {interface} switchport"
    output = ssh.send_command(cmd)
    for line in output.splitlines():
        line = line.strip().lower()
        if "operational mode:" in line:
            return line.split("operational mode:")[1].strip()
    return None


def shutdown_port(ssh, interface):
    debug(f"Shutting down interface {interface}...")
    ssh.enable()
    cmds = [f"interface {interface}", "shutdown", "exit"]
    ssh.send_config_set(cmds)


def find_access_port_for_mac(mac):
    visited_switches = set()
    for switch_ip in SWITCH_IPS:
        debug(f"Checking switch: {switch_ip}")
        if switch_ip in visited_switches:
            continue
        visited_switches.add(switch_ip)

        device = {
            "device_type": "cisco_ios",
            "host": switch_ip,
            "port": SSH_PORT,
            "username": USERNAME,
            "password": PASSWORD,
            "secret": ENABLE_PASSWORD or PASSWORD,
        }

        try:
            ssh = ConnectHandler(**device)
            debug("Connected successfully.")
            mac_table_output = ssh.send_command("show mac address-table")
            formatted_mac = format_mac_for_cisco(mac)
            debug(f"Formatted MAC: {formatted_mac}")
            ports = get_ports_from_mac(formatted_mac, mac_table_output)

            if not ports:
                debug(f"MAC {formatted_mac} not found on {switch_ip}")
                ssh.disconnect()
                continue

            for port in ports:
                port_type = get_port_type(ssh, port)
                debug(f"Found MAC on port {port}, type: {port_type}")
                if port_type and "access" in port_type:
                    shutdown_port(ssh, port)
                    ssh.disconnect()
                    return switch_ip, port

            ssh.disconnect()

        except Exception as e:
            debug(f"Connection error with {switch_ip}: {e}")

    return None, None


def get_mac_from_arping(ip):
    try:
        debug(f"Running arping for IP: {ip}")
        result = subprocess.run(["arping", "-I", "ens192", "-c", "3", ip], capture_output=True, text=True)
        output = result.stdout
        debug(f"Arping output:\n{output}")
        mac_match = re.search(r"from\s+([0-9a-f:]{2}(?::[0-9a-f:]{2}){5})", output, re.IGNORECASE)
        if mac_match:
            mac = mac_match.group(1).lower()
            debug(f"Extracted MAC: {mac}")
            return mac
        else:
            debug("MAC not found in arping output.")
    except Exception as e:
        debug(f"Arping failed: {e}")
    return None


def main():
    debug("Started takedown script.")
    try:
        with open('/var/ossec/logs/takedown-alerts.json', 'r') as f:
            log_data = f.read()
        debug("Loaded takedown-alerts.json")
    except FileNotFoundError:
        debug("File not found.")
        sys.exit(1)

    if '"Endpoints"' not in log_data:
        debug("Server-type not Endpoints. Exiting.")
        sys.exit(0)

    ip_match = re.search(r'"ip"\s*:\s*"([^"]+)"', log_data)
    name_match = re.search(r'"name"\s*:\s*"([^"]+)"', log_data)
    id_match = re.search(r'"agent"\s*:\s*\{[^}]*"id"\s*:\s*"([^"]+)"', log_data)
    rule_id_match = re.search(r'"rule"\s*:\s*\{[^}]*"id"\s*:\s*"([^"]+)"', log_data)

    agent_ip = ip_match.group(1) if ip_match else "N/A"
    agent_name = name_match.group(1) if name_match else "N/A"
    agent_id = id_match.group(1) if id_match else "N/A"
    rule_id = rule_id_match.group(1) if rule_id_match else "shutdown_port"

    debug(f"agent_ip={agent_ip}, agent_name={agent_name}, agent_id={agent_id}, rule_id={rule_id}")

    if agent_ip == "N/A":
        debug("Agent IP missing. Exiting.")
        sys.exit(1)

    mac = get_mac_from_arping(agent_ip)
    if not mac:
        debug("Failed to get MAC. Exiting.")
        sys.exit(1)

    try:
        formatted_mac = format_mac_for_cisco(mac)
        debug(f"Cisco-formatted MAC: {formatted_mac}")
    except ValueError as ve:
        debug(f"MAC formatting failed: {ve}")
        sys.exit(1)

    switch, port = find_access_port_for_mac(mac)

    if switch and port:
        description = f"Port {port} on switch {switch} was shut down due to alert from agent {agent_ip}"
        status = "shutdown_success"
    else:
        description = f"No access port found for MAC {formatted_mac} (agent {agent_ip})"
        status = "shutdown_failed"
        switch = "unknown"
        port = "not_found"

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
        "mac": formatted_mac,
        "ip": agent_ip,
        "port": port,
        "switch": switch,
        "status": status,
        "message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z",  # הוספת timestamp בפורמט UTC ISO
    }

    print(json.dumps(output_data))
    debug("✅ JSON output sent to stdout")


if __name__ == "__main__":
    main()
