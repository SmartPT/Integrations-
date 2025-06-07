import sys
from netmiko import ConnectHandler

# --- CONFIGURATION ---
SWITCH_IPS = [
]
USERNAME = ""
PASSWORD = ""
ENABLE_PASSWORD = ""  # Optional, or same as PASSWORD
SSH_PORT = 22

def enable_port_on_switch(switch_ip, interface):
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
        print(f"[+] Connected to switch {switch_ip}")

        ssh.enable()
        print(f"[!] Bringing up interface {interface}...")

        cmds = [
            f"interface {interface}",
            "no shutdown",
            "exit"
        ]
        output = ssh.send_config_set(cmds)
        print(output)

        ssh.disconnect()
        print(f"[✓] Interface {interface} on switch {switch_ip} is now up.")

    except Exception as e:
        print(f"[!] Failed to enable port on {switch_ip}: {e}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <interface> <switch_ip>")
        sys.exit(1)

    interface = sys.argv[1]       # Example: Gi1/0/26
    switch_ip = sys.argv[2]       # Example: 192.168.0.110

    enable_port_on_switch(switch_ip, interface)

if __name__ == "__main__":
    main()
