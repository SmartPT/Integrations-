import re
import subprocess
import sys
import os
from netmiko import ConnectHandler

# CONFIGURATION
SWITCH_IPS = ["192.168.1.1"]
USERNAME = "your_user"
PASSWORD = "your_pass"
ENABLE_PASSWORD = "your_enable_pass"
SSH_PORT = 22
ARP_INTERFACE = "ens192"  # שנה לפי הצורך

def log(ip, text):
    filepath = f"/var/ossec/logs/{ip}.txt"
    with open(filepath, "a") as f:
        f.write(text + "\n")

def format_mac(mac):
    mac = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return f"{mac[:4]}.{mac[4:8]}.{mac[8:]}" if len(mac) == 12 else None

def get_mac(ip):
    try:
        result = subprocess.run(["arping", "-I", ARP_INTERFACE, "-c", "3", ip], capture_output=True, text=True)
        match = re.search(r"from\s+([0-9a-f:]{2}(?::[0-9a-f:]{2}){5})", result.stdout, re.I)
        return match.group(1).lower() if match else None
    except Exception as e:
        return None

def get_ports(mac, output):
    return [line.split()[-1] for line in output.splitlines() if mac in line.lower()]

def get_port_type(ssh, interface):
    out = ssh.send_command(f"show interface {interface} switchport")
    for line in out.splitlines():
        if "Operational Mode" in line:
            return line.split(":")[1].strip().lower()
    return None

def shutdown_port(ssh, interface):
    ssh.enable()
    ssh.send_config_set([f"interface {interface}", "shutdown", "exit"])

def find_and_shutdown(ip, mac):
    formatted_mac = format_mac(mac)
    if not formatted_mac:
        log(ip, f"❌ Invalid MAC format: {mac}")
        return

    log(ip, f"🧬 MAC (formatted): {formatted_mac}")

    for switch_ip in SWITCH_IPS:
        try:
            ssh = ConnectHandler(
                device_type="cisco_ios", host=switch_ip, username=USERNAME,
                password=PASSWORD, secret=ENABLE_PASSWORD, port=SSH_PORT
            )
            ssh.enable()
            output = ssh.send_command("show mac address-table")
            ports = get_ports(formatted_mac, output)

            for port in ports:
                if get_port_type(ssh, port) == "access":
                    shutdown_port(ssh, port)
                    log(ip, f"✅ Shut down port {port} on switch {switch_ip}")
                    ssh.disconnect()
                    return

            ssh.disconnect()
        except Exception as e:
            log(ip, f"❌ Failed to connect or execute on {switch_ip}: {e}")

    log(ip, f"❌ MAC {formatted_mac} not found on any switch")

def main():
    if len(sys.argv) != 2:
        print("❌ Usage: block_port.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]

    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        log(ip, "❌ Invalid IP format")
        sys.exit(1)

    log(ip, f"🔍 Searching for MAC for IP: {ip}")
    mac = get_mac(ip)

    if not mac:
        log(ip, "❌ MAC not found via arping")
        sys.exit(1)

    log(ip, f"🧭 Found MAC: {mac}")
    find_and_shutdown(ip, mac)

if __name__ == "__main__":
    main()
