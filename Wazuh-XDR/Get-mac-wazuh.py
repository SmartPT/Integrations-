#!/usr/bin/env python3
"""
Fetch MAC address from Wazuh API using data in:
    /var/ossec/logs/extracted_data.json

• No authentication call – uses a pre-issued JWT token
  (env var WAZUH_TOKEN or hard-coded fallback).
"""

import os
import re
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ─── CONFIG ─────────────────────────────────────────────────────────────────
WAZUH_URL   = os.getenv("WAZUH_URL",   "https://127.0.0.1:55000")
WAZUH_TOKEN = os.getenv("WAZUH_TOKEN", "ey..")
VERIFY_TLS  = False                      # change to True with valid certs
TIMEOUT     = 10
JSON_PATH   = "/var/ossec/logs/extracted_data.json"
REGEX = {
    "agent_id": r'"agent":\s*{[^}]*?"id"\s*:\s*"([^"]+)"',
    "agent_ip": r'"agent":\s*{[^}]*?"ip"\s*:\s*"([^"]+)"',
}
# ────────────────────────────────────────────────────────────────────────────

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

def get_mac(agent_id: str, agent_ip: str) -> str:
    # 1) find interface for the given IP
    netaddr = api_get(f"/syscollector/{agent_id}/netaddr")
    iface = next(
        (it["iface"] for it in netaddr["data"]["affected_items"]
         if it.get("proto") == "ipv4" and it.get("address") == agent_ip),
        None,
    )
    if not iface:
        print(f"❌ interface for IP {agent_ip} not found", file=sys.stderr)
        sys.exit(3)

    # 2) fetch its MAC
    netiface = api_get(f"/syscollector/{agent_id}/netiface")
    mac = next(
        (it["mac"] for it in netiface["data"]["affected_items"]
         if it["name"] == iface),
        None,
    )
    if not mac:
        print(f"❌ MAC for interface {iface} not found", file=sys.stderr)
        sys.exit(4)
    return mac

def main():
    raw = read_json_text(JSON_PATH)
    agent_id, agent_ip = extract_id_ip(raw)
    mac = get_mac(agent_id, agent_ip)
    print(mac)

if __name__ == "__main__":
    main()
