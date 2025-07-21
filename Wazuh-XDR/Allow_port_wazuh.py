#!/usr/bin/env python3 
import sys
import os
from netmiko import ConnectHandler
 
# --- CONFIGURATION ---
USERNAME         = ""
PASSWORD         = ""
ENABLE_PASSWORD  = ""
SSH_PORT         = 22
LOG_PATH         = "/var/ossec/logs"
 
def parse_log_file(ip):
    file_path = os.path.join(LOG_PATH, f"{ip}.txt")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file {file_path} does not exist: {file_path}")
 
    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3:
                switch_ip, interface, logged_ip = parts
                if logged_ip == ip:
                    return interface, switch_ip
 
    raise ValueError(f"No valid switch/port entry found for IP {ip} in {file_path}")
 
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
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <agent_ip>")
        sys.exit(1)
 
    ip = sys.argv[1]
 
    try:
        interface, switch_ip = parse_log_file(ip)
        print(f"[i] Found interface {interface} on switch {switch_ip} for IP {ip}")
        enable_port_on_switch(switch_ip, interface)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
 
if __name__ == "__main__":
    main()
