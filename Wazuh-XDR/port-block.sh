#!/bin/bash

read INPUT_JSON

# חילוץ ה-IP בעזרת jq
IP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data["Agent.ip"]')

# בדיקת תקינות
if [[ -z "$IP" || "$IP" == "null" ]]; then
  echo "❌ Failed to extract IP"
  exit 1
fi

# יצירת קובץ טקסט עבור ה-IP
echo "🔧 Starting port block for $IP" > "/var/ossec/logs/${IP}.txt"

# קריאה לסקריפט פייתון עם פרמטר ה-IP
python3 /var/ossec/active-response/bin/block_port.py "$IP"
