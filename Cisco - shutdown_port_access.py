import re
import subprocess
import sys
from netmiko import ConnectHandler

# --- CONFIGURATION ---
SWITCH_IPS = [

]

USERNAME = ""
PASSWORD = ""
SSH_PORT = 22
ENABLE_PASSWORD = ""  # Set if needed

# --- UTILITIES ---

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
    mode = None
    for line in output.splitlines():
        line = line.strip().lower()
        if "operational mode:" in line:
            mode = line.split("operational mode:")[1].strip()
            break
    return mode


def shutdown_port(ssh, interface):
    print(f"[!] Entering enable mode...")
    ssh.enable()
    print(f"[!] Shutting down interface {interface}...")
    cmds = [
        f"interface {interface}",
        "shutdown",
        "exit"
    ]
    output = ssh.send_config_set(cmds)
    print(output)


def find_access_port_for_mac(mac):
    visited_switches = set()

    def recursive_search(mac, switches):
        for switch_ip in switches:
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
                print(f"[+] Connected to switch {switch_ip} - searching MAC {mac}")

                mac_table_output = ssh.send_command("show mac address-table")
                formatted_mac = format_mac_for_cisco(mac)
                ports = get_ports_from_mac(formatted_mac, mac_table_output)

                if not ports:
                    print(f"[-] MAC {formatted_mac} not found on {switch_ip}")
                    ssh.disconnect()
                    continue

                for port in ports:
                    port_type = get_port_type(ssh, port)
                    print(f"    Found MAC {formatted_mac} on port {port} with port type '{port_type}'")

                    if port_type and "access" in port_type:
                        print(f"[✓] Access port found: Switch {switch_ip} Port {port}")
                        shutdown_port(ssh, port)
                        ssh.disconnect()
                        return switch_ip, port

                ssh.disconnect()

            except Exception as e:
                print(f"[!] Error connecting to {switch_ip}: {e}")

        return None, None

    return recursive_search(mac, SWITCH_IPS)


def get_mac_from_arping(ip):
    try:
        result = subprocess.run(["arping", "-I", "ens192", "-c", "3", ip], capture_output=True, text=True)
        output = result.stdout
        mac_match = re.search(r"from\s+([0-9a-f:]{2}(?::[0-9a-f:]{2}){5})", output, re.IGNORECASE)
        #mac_match = re.search(r"\[([0-9a-f:]{17})\]", output, re.IGNORECASE)
        if mac_match:
            mac = mac_match.group(1).lower()
            print(f"[+] MAC address for IP {ip} is {mac}")
            return mac
        else:
            print(f"[-] MAC address not found in arping output for IP {ip}")
            return None
    except Exception as e:
        print(f"[!] Failed to run arping: {e}")
        return None


def main():
    try:
        with open('/var/ossec/logs/takedown-alerts.json', 'r') as f:
            log_data = f.read()
    except FileNotFoundError:
        print("[!] Log file not found.")
        sys.exit(1)

    if not re.search(r'"server-type"\s*:\s*"DimriEndpoints"', log_data):
        print("[!] Server type is not DimriEndpoints. Exiting.")
        sys.exit(0)

    parent_user_match = re.search(r'"agent"\s*:\s*\{.*?"ip"\s*:\s*"([^"]+)"', log_data, re.DOTALL)
    if not parent_user_match:
        print("[!] Parent user IP not found. Exiting.")
        sys.exit(1)

    parent_user_ip = parent_user_match.group(1)
    print(f"[+] Parent user IP found: {parent_user_ip}")

    mac = get_mac_from_arping(parent_user_ip)
    if not mac:
        print("[!] Could not get MAC address. Exiting.")
        sys.exit(1)

    try:
        formatted_mac = format_mac_for_cisco(mac)
    except ValueError as ve:
        print(f"[!] MAC format error: {ve}")
        sys.exit(1)

    print(f"[+] Cisco-formatted MAC: {formatted_mac}")

    switch, port = find_access_port_for_mac(mac)
    if switch and port:
        print(f"\n[✓] MAC {formatted_mac} was found on switch {switch}, port {port} and has been shut down.")
    else:
        print(f"[✗] Access port for MAC {formatted_mac} not found on any switch.")


if __name__ == "__main__":
    main()