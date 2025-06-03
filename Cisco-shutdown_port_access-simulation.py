import sys
from netmiko import ConnectHandler

# --- CONFIGURATION ---
SWITCH_IPS = [
]
USERNAME = ""
PASSWORD = ""
SSH_PORT = 22
ENABLE_PASSWORD = ""  # Fill this in if different from PASSWORD

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
    ssh.enable()  # Important: enter privileged EXEC mode
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
                "secret": ENABLE_PASSWORD or PASSWORD,  # fallback if no separate enable password
            }

            try:
                ssh = ConnectHandler(**device)
                print(f"[+] Connected to switch {switch_ip} - searching MAC {mac}")

                mac_table_output = ssh.send_command("show mac address-table")
                ports = get_ports_from_mac(mac, mac_table_output)

                if not ports:
                    print(f"[-] MAC {mac} not found on {switch_ip}")
                    ssh.disconnect()
                    continue

                for port in ports:
                    port_type = get_port_type(ssh, port)
                    print(f"    Found MAC on port {port} with port type '{port_type}'")

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

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <target_mac>")
        sys.exit(1)

    target_mac = sys.argv[1].lower().replace("-", ":")
    if not ":" in target_mac and len(target_mac) == 12:
        target_mac = ":".join(target_mac[i:i+2] for i in range(0, 12, 2))

    switch, port = find_access_port_for_mac(target_mac)
    if switch and port:
        print(f"\n[✓] MAC {target_mac} was on switch {switch}, port {port}, which is now shut down.")
    else:
        print(f"[✗] Access port for MAC {target_mac} not found on any switch.")

if __name__ == "__main__":
    main()
