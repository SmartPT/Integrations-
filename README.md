# SmartPT Integrations

A curated collection of Python and Shell scripts designed to streamline IT security and network operations across Cisco, Citrix, and Cortex XDR environments.

---

## 📂 Repository Structure

- **Cisco/** — Scripts for managing network ports and interfaces.
- **Citrix/** — Tools for Citrix session management and site identification.
- **Cortex/** — Security automation scripts utilizing Cortex XDR.

---

## 🟦 Cisco Scripts

### 1. `get_port_from_mac.py`
- **Purpose**: Identifies the physical switch port connected to a specified MAC address on a Cisco switch.
- **Prerequisites**:
  - Python 3.7+
  - `paramiko` library for SSH connections
  - Network access to the Cisco switch
- **Usage**:
  ```bash
  python get_port_from_mac.py --mac 00:11:22:33:44:55

Functionality: Connects to the Cisco switch via SSH, executes commands to search for the MAC address in the MAC address table, and returns the associated interface. 


2. shutdown_port_access.py

Purpose: Disables (shuts down) a specific port on a Cisco switch, typically to isolate unauthorized or compromised devices.

Prerequisites:

Same as above


Usage:

python shutdown_port_access.py --interface GigabitEthernet0/1

Functionality: Connects to the switch and issues the shutdown command on the specified interface. 


3. up_port_access.py

Purpose: Re-enables a previously shut down port on a Cisco switch.

Prerequisites:

Same as above


Usage:

python up_port_access.py --interface GigabitEthernet0/1

Functionality: Connects to the switch and issues the no shutdown command on the specified interface. 


4. shutdown_port_access-simulation.py

Purpose: Simulates the shutdown of a port without executing the actual command, useful for testing and validation.

Prerequisites:

Same as above


Usage:

python shutdown_port_access-simulation.py --interface GigabitEthernet0/1

Functionality: Performs all steps of the shutdown process except the execution of the shutdown command, allowing administrators to verify the process without impacting the network. 



---

🟨 Citrix Scripts

5. GetSiteID.sh

Purpose: Retrieves the Site ID of the Citrix deployment.

Prerequisites:

Access to Citrix environment

Execution permissions for shell scripts


Usage:

bash GetSiteID.sh

Functionality: Executes commands to query the Citrix configuration and extracts the Site ID. 


6. Logoff-Sessions.py

Purpose: Logs off active user sessions in a Citrix environment.

Prerequisites:

Python 3.7+

Citrix SDK or API access


Usage:

python Logoff-Sessions.py --user username

Functionality: Connects to the Citrix environment and issues commands to log off the specified user's session. 


7. run_logoff_limited.sh

Purpose: Executes the Logoff-Sessions.py script with specific constraints, such as time windows or user groups.

Prerequisites:

Execution permissions for shell scripts

Proper configuration of constraints within the script


Usage:

bash run_logoff_limited.sh

Functionality: Wraps the Python script execution with additional logic to enforce specified limitations, ensuring controlled session management. 



---

🟥 Cortex Script

8. isolate.py

Purpose: Isolates a compromised machine from the network using Cortex XDR.

Prerequisites:

Python 3.7+

Cortex XDR API access

requests library for HTTP requests


Usage:

python isolate.py --endpoint-id 1234567890

Functionality: Sends an API request to Cortex XDR to isolate the specified endpoint, effectively cutting off its network access to prevent the spread of threats. 



---

📦 Requirements

General:

Python 3.7+

Shell environment for .sh scripts


Python Libraries:

paramiko for SSH connections (Cisco scripts)

requests for HTTP requests (Cortex script)


Access:

Network access to Cisco switches

Appropriate permissions in Citrix and Cortex XDR environments 




---

🛡️ Disclaimer

These scripts are intended for use by experienced IT professionals. Ensure thorough testing in a controlled environment before deploying in production. 


---

🤝 Contributions

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements or additional scripts. 


---
