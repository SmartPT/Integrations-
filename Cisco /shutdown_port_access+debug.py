import sys
import json
import os
import requests
from datetime import datetime, timedelta

LOG_FILE = "/var/ossec/logs/active-responses.log"
OUTPUT_FILE = "/var/ossec/logs/extracted_data.json"
THROTTLE_FILE = "/var/ossec/logs/switchthrottle_tracker.json"
API_ENDPOINT = "https://xx.smartpt.co.il/alerts"
THROTTLE_INTERVAL = timedelta(minutes=1)
SHA256_KEY = ""

def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{datetime.now()}] {message}\n")

def save_throttle_data(throttle_data):
    with open(THROTTLE_FILE, "w") as json_file:
        json.dump(throttle_data, json_file)

def load_throttle_data():
    if os.path.exists(THROTTLE_FILE):
        try:
            with open(THROTTLE_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            log_message(f"Error: Malformed JSON in {THROTTLE_FILE}")
            return {}
    return {}

def should_send_alert(host, rule_id):
    if host == "N/A" or rule_id == "N/A":
        log_message(f"Invalid host ({host}) or rule_id ({rule_id}), skipping alert.")
        return False

    throttle_data = load_throttle_data()
    current_time = datetime.now()
    key = f"{host}_{rule_id}"

    if key in throttle_data:
        last_sent_time = datetime.strptime(throttle_data[key], "%Y-%m-%d %H:%M:%S")
        if current_time - last_sent_time < THROTTLE_INTERVAL:
            log_message(f"Alert throttled for {key}. Last sent at {last_sent_time}.")
            return False

    throttle_data[key] = current_time.strftime("%Y-%m-%d %H:%M:%S")
    save_throttle_data(throttle_data)
    return True

def post_to_api(data):
    data['sha256'] = SHA256_KEY
    filtered_data = {k: v for k, v in data.items() if v not in [None, "", "N/A"]}

    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(API_ENDPOINT, headers=headers, json=filtered_data)

        log_message(f"POST to {API_ENDPOINT} with data: {json.dumps(filtered_data, indent=2)}")
        log_message(f"Response Status Code: {response.status_code}")
        log_message(f"Response Body: {response.text}")

        if response.status_code != 200:
            log_message(f"Failed to post data to {API_ENDPOINT}: {response.status_code}")
        else:
            log_message("Data successfully posted")
    except Exception as e:
        log_message(f"Error posting data to API: {e}")

if __name__ == "__main__":
    log_message("Starting smartpt_forwarder from stdin")

    try:
        input_data = json.load(sys.stdin)
    except Exception as e:
        log_message(f"Error reading input JSON: {e}")
        sys.exit(1)

    input_data.setdefault("agent_name", "N/A")
    input_data.setdefault("rule_id", "N/A")

    if should_send_alert(input_data['agent_name'], input_data['rule_id']):
        with open(OUTPUT_FILE, "w") as output_file:
            json.dump(input_data, output_file)
        log_message(f"Input data saved to {OUTPUT_FILE}")
        post_to_api(input_data)
    else:
        log_message(f"Alert not sent due to throttle for {input_data['agent_name']} and rule {input_data['rule_id']}")
