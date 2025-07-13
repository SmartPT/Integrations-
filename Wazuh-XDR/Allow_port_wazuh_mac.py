#!/usr/bin/env python3
"""
enable_port.py [<agent_id> <agent_ip> | -]

• אם המזהים מגיעים כפרמטרים → משתמש בהם ישירות
• אם מתקבל "-" → קורא JSON מ-STDIN ומחלץ מתוכו agent_id + agent_ip
• מאתר בקובץ הלוג /var/ossec/logs/<agent_ip>.txt את הסוויץ' והפורט
• מבצע 'no shutdown' לפורט בסוויץ'

תלויות: netmiko
"""

import sys
import os
import re
from netmiko import ConnectHandler

# ─── CONFIG ─────────────────────────────────────────────────────────────────
LOG_DIR          = "/var/ossec/logs"
USERNAME         = ""
PASSWORD         = ""
ENABLE_PASSWORD  = ""
SSH_PORT         = 22
REGEX = {
    "agent_id": r'"agent":\s*{[^}]*?"id"\s*:\s*"([^"]+)"',
    "agent_ip": r'"agent":\s*{[^}]*?"ip"\s*:\s*"([^"]+)"',
}
# ────────────────────────────────────────────────────────────────────────────


def parse_stdin_json() -> tuple[str, str]:
    """Read JSON from stdin and extract agent_id + agent_ip."""
    data = sys.stdin.read()
    id_m = re.search(REGEX["agent_id"], data, re.S)
    ip_m = re.search(REGEX["agent_ip"], data, re.S)
    if not id_m or not ip_m:
        sys.exit("❌ Could not extract agent_id / agent_ip from stdin JSON")
    return id_m.group(1), ip_m.group(1)


def read_log(agent_ip: str) -> tuple[str, str]:
    """Return (interface, switch_ip) recorded when the port was shut down."""
    path = os.path.join(LOG_DIR, f"{agent_ip}.txt")
    if not os.path.isfile(path):
        sys.exit(f"❌ Log file {path} not found")

    switch_ip, interface = None, None
    with open(path) as f:
        for line in f:
            if "Shut down port" in line or "Interface" in line:
                parts = line.split()
                try:
                    interface = parts[parts.index("port") + 1]
                    switch_ip = parts[parts.index("switch") + 1]
                except (ValueError, IndexError):
                    continue

    if not switch_ip or not interface:
        sys.exit("❌ Could not parse switch/interface from log")
    return interface, switch_ip


def enable_port(switch_ip: str, interface: str):
    dev = {
        "device_type": "cisco_ios",
        "host": switch_ip,
        "username": USERNAME,
        "password": PASSWORD,
        "secret": ENABLE_PASSWORD or PASSWORD,
        "port": SSH_PORT,
    }
    try:
        with ConnectHandler(**dev) as ssh:
            ssh.enable()
            out = ssh.send_config_set([f"interface {interface}", "no shutdown", "exit"])
            print(out)
            print(f"✅ Interface {interface} on {switch_ip} is now up")
    except Exception as e:
        sys.exit(f"❌ Failed to enable port: {e}")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "-":
        agent_id, agent_ip = parse_stdin_json()
    elif len(sys.argv) == 3:
        agent_id, agent_ip = sys.argv[1], sys.argv[2]
    else:
        sys.exit("Usage:\n  python enable_port.py <agent_id> <agent_ip>\n  cat alert.json | python enable_port.py -")

    print(f"🔎 agent_id={agent_id}  agent_ip={agent_ip}")
    iface, sw = read_log(agent_ip)
    print(f"➡  Bringing up {iface} on switch {sw}")
    enable_port(sw, iface)


if __name__ == "__main__":
    main()
