#!/bin/bash

read INPUT_JSON

IP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data["Agent.ip"]')

if [[ -z "$IP" || "$IP" == "null" ]]; then
  echo "❌ Failed to extract IP"
  exit 1
fi

echo "🟢 Starting port allow for $IP"
#python3 /var/ossec/active-response/bin/port_allow.py "$IP"
