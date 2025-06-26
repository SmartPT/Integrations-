# ⚙️ SmartPT Integrations

A curated collection of Python and Shell scripts designed to streamline IT security and network operations across **Cisco**, **Citrix**, **Cortex XDR**, and **Wazuh** environments.

---

## 📁 Repository Structure

- **Cisco/** – Network automation scripts (port control, MAC tracing).
- **Citrix/** – Session and site management utilities.
- **Cortex/** – API-based endpoint isolation.
- **Wazuh-XDR/** – Wazuh Active Response integrations for automated port blocking/unblocking.

---

## 🟦 Cisco Scripts

### 1. `get_port_from_mac.py`
- **Purpose**: Identifies the switch port a MAC address is connected to.
- **Requirements**:
  - Python 3.7+
  - `paramiko`
  - SSH access to Cisco switch
- **Usage**:
  ```bash
  python get_port_from_mac.py --mac 00:11:22:33:44:55
  ```

### 2. `shutdown_port_access.py`
- **Purpose**: Shuts down a specific switch interface (to isolate a device).
- **Usage**:
  ```bash
  python shutdown_port_access.py --interface GigabitEthernet0/1
  ```

### 3. `up_port_access.py`
- **Purpose**: Brings a previously shut-down port back online.
- **Usage**:
  ```bash
  python up_port_access.py --interface GigabitEthernet0/1
  ```

### 4. `shutdown_port_access-simulation.py`
- **Purpose**: Simulates port shutdown (no actual changes applied).
- **Usage**:
  ```bash
  python shutdown_port_access-simulation.py --interface GigabitEthernet0/1
  ```

---

## 🟨 Citrix Scripts

### 5. `GetSiteID.sh`
- **Purpose**: Retrieves Citrix Site ID from the environment.
- **Usage**:
  ```bash
  bash GetSiteID.sh
  ```

### 6. `Logoff-Sessions.py`
- **Purpose**: Logs off a user from their active Citrix session.
- **Usage**:
  ```bash
  python Logoff-Sessions.py --user username
  ```

### 7. `run_logoff_limited.sh`
- **Purpose**: Adds logic (e.g., time filters, user groups) to session logoffs.
- **Usage**:
  ```bash
  bash run_logoff_limited.sh
  ```

---

## 🟥 Cortex Script

### 8. `isolate.py`
- **Purpose**: Isolates a machine via Cortex XDR API.
- **Usage**:
  ```bash
  python isolate.py --endpoint-id 1234567890
  ```

---

## 🟪 Wazuh-XDR Scripts

### 9. `port-block.sh`
- **Purpose**: Triggered by Wazuh Active Response to isolate a malicious endpoint.
- **Function**:
  - Reads Wazuh alert JSON
  - Extracts IP
  - Logs IP to `/var/ossec/logs/<ip>.txt`
  - Invokes `port_block.py`

### 10. `port_block.py`
- **Purpose**: Uses `arping` to find MAC and shuts down the related switch port.
- **Function**:
  - Gets MAC of IP via ARP
  - Looks for MAC on configured switches
  - Disables the appropriate interface
  - Logs MAC, switch, interface, and action results

### 11. `port-allow.sh`
- **Purpose**: Restores a port previously blocked by Wazuh.
- **Function**:
  - Reads from `/var/ossec/logs/<ip>.txt`
  - Calls `port_allow.py` with stored data

### 12. `port_allow.py`
- **Purpose**: Enables a port by reading previously stored info.
- **Function**:
  - Reads the stored MAC/switch/interface
  - Connects via SSH to bring the port back up

---

## 🛠️ Prerequisites for Wazuh-XDR

- Python 3.7+
- `netmiko` library
- `arping` utility (Linux)
- SSH access to switches
- Wazuh Manager with Active Response enabled

---

## 🚀 Wazuh Integration Flow

1. Wazuh detects malicious behavior on an endpoint.
2. Wazuh triggers `port-block.sh` via Active Response.
3. IP is logged and passed to `port_block.py`.
4. The port is located and shut down.
5. When resolved, `port-allow.sh` can be triggered manually or automatically.
6. `port_allow.py` brings the port back online using stored data.

---

## 📦 Requirements

**General:**
- Python 3.7+
- Bash-compatible shell

**Python Libraries:**
- `paramiko` (for Cisco)
- `requests` (for Cortex)
- `netmiko` (for Wazuh-XDR)

**Access:**
- Cisco switch SSH access
- Citrix API or SDK access
- Cortex XDR API credentials

---

## 🛡️ Disclaimer

These scripts are intended for use by experienced IT professionals. Test thoroughly in staging before use in production environments.

---

## 🤝 Contributions

Contributions are welcome! Fork the repo and submit a pull request with improvements or new features.
