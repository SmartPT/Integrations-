import re
import json
import requests
import os
from datetime import datetime
from ipaddress import ip_address, ip_network

# Configuration
log_file_path = "/var/ossec/logs/networkviolation.json"  # Path to the log file
cortex_url = "https://api-example.xdr.il.paloaltonetworks.com/public_api/v1/endpoints/get_endpoint"  # Cortex API URL
isolate_endpoint_url = "https://api-example.xdr.il.paloaltonetworks.com/public_api/v1/endpoints/isolate"  # Endpoint isolation URL
api_auth_id = "1"  # Replace with your x-xdr-auth-id
api_token = ""  # Replace with your authorization token
last_run_file = "/var/ossec/logs/last_run_isolate_time.txt"  # File to store the last run timestamp

# Define the IP ranges
ip_ranges_to_check = [
    "192.168.102.0/22",  # Covers 192.168.102.0 - 192.168.105.255
    "192.168.108.0/32",  # Covers 192.168.108.0 - 192.168.108.255
    "192.168.112.0/22"  # Covers 192.168.112.0 - 192.168.114.255
]

# Parse log file and extract valid IPs
def parse_logs_with_regex(file_path, ip_ranges):
    try:
        with open(file_path, 'r') as file:
            raw_data = file.read()

        # Regular expression to extract source IP addresses
        ip_pattern = r'"ipAddress":"(\d+\.\d+\.\d+\.\d+)"'
        found_ips = re.findall(ip_pattern, raw_data)

        # Validate and check IPs in the specified ranges
        valid_ips = []
        for ip in found_ips:
            if any(ip_address(ip) in ip_network(range, strict=False) for range in ip_ranges):
                valid_ips.append(ip)

        return valid_ips
    except Exception as e:
        print(f"An error occurred while parsing logs: {e}")
        return []

# Query the Cortex API with the extracted IP
def query_cortex_api(ip_address):
    headers = {
        "x-xdr-auth-id": api_auth_id,
        "Authorization": api_token,
        "Content-Type": "application/json",
    }
    data = {
        "request_data": {
            "search_from": 0,
            "search_to": 1,
            "sort": {
                "field": "endpoint_id",
                "keyword": "asc",
            },
            "filters": [
                {
                    "field": "ip_list",
                    "operator": "in",
                    "value": [ip_address],
                }
            ],
        }
    }
    response = requests.post(cortex_url, headers=headers, json=data)
    return response

# Isolate the endpoint using the Cortex API
def isolate_endpoint(endpoint_id):
    headers = {
        "x-xdr-auth-id": api_auth_id,
        "Authorization": api_token,
        "Content-Type": "application/json",
    }
    data = {
        "request_data": {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": [endpoint_id],
                }
            ]
        }
    }

    try:
        response = requests.post(isolate_endpoint_url, headers=headers, json=data)
        if response.status_code == 200:
            print(f"Successfully isolated endpoint {endpoint_id}")
        else:
            print(f"Failed to isolate endpoint {endpoint_id}. Status code: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"An error occurred while isolating the endpoint: {e}")

# Check if the script was last run more than 10 minutes ago
def can_run_script():
    if os.path.exists(last_run_file):
        with open(last_run_file, "r") as file:
            last_run_time = file.read().strip()
        last_run_time = datetime.strptime(last_run_time, "%Y-%m-%d %H:%M:%S")
        if (datetime.now() - last_run_time).total_seconds() < 10800:
            return False  # Less than 10 minutes ago, don't run the script
    return True

# Update the timestamp of the last script run
def update_last_run_time():
    with open(last_run_file, "w") as file:
        file.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Main function
def main():
    if not can_run_script():
        print("Script already ran in the last 10 minutes. Exiting.")
        return

    # Parse log file for valid IPs
    valid_ips = parse_logs_with_regex(log_file_path, ip_ranges_to_check)
    if not valid_ips:
        print("No valid IPs found in the specified ranges.")
        return

    print(f"Valid IPs found: {valid_ips}")

    for ip in valid_ips:
        # Query the Cortex API with the extracted IP
        response = query_cortex_api(ip)
        if response.status_code == 200:
            response_data = response.json()
            endpoints = response_data.get("reply", {}).get("endpoints", [])
            if endpoints:
                for endpoint in endpoints:
                    endpoint_id = endpoint.get("endpoint_id")
                    print(f"Endpoint ID: {endpoint_id}")

                    # Isolate the endpoint
                    isolate_endpoint(endpoint_id)
            else:
                print(f"No endpoints found for IP: {ip}")
        else:
            print(f"Failed to query Cortex API for IP: {ip}. Status code: {response.status_code}")
            print(f"Response: {response.text}")

    # Update the last run time
    update_last_run_time()

if __name__ == "__main__":
    main()
