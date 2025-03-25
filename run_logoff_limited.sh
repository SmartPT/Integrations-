#!/bin/bash
read INPUT_JSON
echo $INPUT_JSON > /var/ossec/logs/citrix.json
# Define variables
PYTHON_SCRIPT="/var/ossec/active-response/bin/citrix/logoff.py"  # Change this to your Python script
LOG_FILE="/tmp/python_script_log.txt"
MAX_RUNS=6
TIME_WINDOW=3600  # One hour in seconds

# Ensure log file exists
touch "$LOG_FILE"

# Remove old entries (older than 1 hour)
NOW=$(date +%s)
awk -v now="$NOW" -v window="$TIME_WINDOW" '$1 > now - window' "$LOG_FILE" > "$LOG_FILE.tmp"
mv "$LOG_FILE.tmp" "$LOG_FILE"

# Count executions in the last hour
RUN_COUNT=$(wc -l < "$LOG_FILE")

# Check if we can run the script
if [ "$RUN_COUNT" -lt "$MAX_RUNS" ]; then
    # Log the execution
    echo "$NOW" >> "$LOG_FILE"

    # Run the Python script
    python3 "$PYTHON_SCRIPT"
else
    echo "Execution limit reached. Try again later."
fi




