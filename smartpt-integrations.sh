#dont use! didnt tested yet
#!/bin/bash
# smartpt-integrations — config-driven with server-type filter
set -euo pipefail

BASE_DIR="/var/ossec/active-response/bin"
CONF_FILE="${CONF_FILE:-$BASE_DIR/actions.conf}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

GLOBAL_MAX_UNIQUE="${GLOBAL_MAX_UNIQUE:-5}"
RATE_DIR="${RATE_DIR:-/var/ossec/active-response/tmp}"
mkdir -p "$RATE_DIR"

# ---- Read full stdin into INPUT_JSON ----
INPUT_JSON=""
while IFS= read -r line; do INPUT_JSON+="${line}"; done

# ---- Extract rule_id / agent_id / agent_name via regex (works on non-JSON) ----
read -r RULE_ID AGENT_ID AGENT_NAME <<'PYOUT'
$(python3 - <<'PY'
import sys,re
s=sys.stdin.read()
g=lambda rx: (re.search(rx, s, re.DOTALL).group(1) if re.search(rx, s, re.DOTALL) else "")
agent_id   = g(r'"agent"\s*:\s*{[^}]*?"id"\s*:\s*"([^"]+)"')
agent_name = g(r'"agent"\s*:\s*{[^}]*?"name"\s*:\s*"([^"]+)"')
rule_id    = g(r'"rule"\s*:\s*{[^}]*?"id"\s*:\s*"([^"]+)"') or g(r'"rule"\s*:\s*{[^}]*?"id"\s*:\s*(\d+)')
print(rule_id or "", agent_id or "", agent_name or "")
PY
) <<< "$INPUT_JSON"
PYOUT

[[ -n "$RULE_ID" ]] || { echo "ERROR: rule.id not found" >&2; exit 2; }
AGENT_KEY="${AGENT_ID:-${AGENT_NAME:-}}"
[[ -n "$AGENT_KEY" ]] || { echo "ERROR: agent.id/name not found" >&2; exit 2; }

# ---- Helpers ----
trim(){ sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
csv_has(){ local needle="$1" csv="$2"; IFS=',' read -ra L <<<"$csv"; for x in "${L[@]}"; do [[ "$(echo "$x"|trim)" == "$needle" ]] && return 0; done; return 1; }

# ---- Find matching action in actions.conf ----
ACTION_PATH=""; ACTION_ENABLED="true"; ACTION_LOG=""
ACTION_MAX_UNIQUE="$GLOBAL_MAX_UNIQUE"; ACTION_EXCLUDE=""; ACTION_ST_REX=""

[[ -f "$CONF_FILE" ]] || { echo "ERROR: config not found: $CONF_FILE" >&2; exit 2; }

while IFS= read -r raw; do
  [[ -z "${raw// }" || "${raw}" =~ ^# ]] && continue
  declare -A kv=(); IFS=';' read -ra parts <<<"$raw"
  for p in "${parts[@]}"; do
    k="${p%%=*}"; v="${p#*=}"; k="$(echo "$k"|trim)"; v="$(echo "$v"|trim)"
    [[ -n "$k" ]] && kv["$k"]="$v"
  done
  rules="${kv[rules]:-}"; action="${kv[action]:-}"
  [[ -n "$rules" && -n "$action" ]] || continue
  if csv_has "$RULE_ID" "$rules"; then
    ACTION_PATH="$action"
    ACTION_ENABLED="${kv[enabled]:-true}"
    ACTION_LOG="${kv[log]:-}"
    ACTION_MAX_UNIQUE="${kv[max_unique_per_hour]:-$GLOBAL_MAX_UNIQUE}"
    ACTION_EXCLUDE="${kv[exclude_agents]:-}"
    ACTION_ST_REX="${kv[server_type_pattern]:-}"
    break
  fi
done < "$CONF_FILE"

[[ -n "$ACTION_PATH" ]] || { echo "No action mapped for rule.id=$RULE_ID" >&2; exit 2; }
[[ "$ACTION_ENABLED" == "true" ]] || { echo "Action disabled for rule.id=$RULE_ID"; exit 0; }

# ---- Exclude by agent.name (if present) ----
if [[ -n "$ACTION_EXCLUDE" && -n "$AGENT_NAME" ]]; then
  if csv_has "$AGENT_NAME" "$ACTION_EXCLUDE"; then
    echo "Excluded agent.name '$AGENT_NAME' for rule.id=$RULE_ID"
    exit 0
  fi
fi

# ---- Optional server-type regex filter ----
# If set and DOES NOT match payload, skip this action.
if [[ -n "$ACTION_ST_REX" ]]; then
  MATCHED="$("$PYTHON_BIN" - <<'PY'
import sys,re,os
pattern=os.environ.get("ST_REX","")
s=sys.stdin.read()
try:
    rx=re.compile(pattern, re.DOTALL)
    print("YES" if rx.search(s) else "NO")
except re.error as e:
    print("BAD", e)
PY
  <<< "$INPUT_JSON"
  )"
  # read first word only (YES/NO)
  MATCHED=$(echo "$MATCHED" | awk '{print $1}')
  if [[ "$MATCHED" == "BAD" ]]; then
    echo "server_type_pattern is invalid regex: $ACTION_ST_REX" >&2
    exit 2
  fi
  if [[ "$MATCHED" == "NO" ]]; then
    echo "server_type_pattern not matched; skipping action for rule.id=$RULE_ID"
    exit 0
  fi
fi

# ---- Per-action rate limit (override global) ----
RATE_FILE="$RATE_DIR/rlimit.$(echo "$ACTION_PATH" | tr '/ ' '__').log"
exec 9>"$RATE_FILE.lock" || true
flock -n 9 || { echo "Rate-limit lock busy"; exit 5; }

NOW=$(date +%s); CUTOFF=$((NOW - 3600))
[[ -f "$RATE_FILE" ]] || : > "$RATE_FILE"
TMP="$RATE_FILE.tmp.$$"
awk -v c="$CUTOFF" 'NF && $1+0 >= c {print $0}' "$RATE_FILE" > "$TMP" || true

UNIQUE_COUNT=$(awk '{print $2}' "$TMP" | sort -u | wc -l | tr -d ' ')
AGENT_ALREADY_RAN=$(awk -v id="$AGENT_KEY" '$2==id' "$TMP" | wc -l | tr -d ' ')

if [[ "$UNIQUE_COUNT" -lt "$ACTION_MAX_UNIQUE" || "$AGENT_ALREADY_RAN" -gt 0 ]]; then
  echo "$NOW $AGENT_KEY" >> "$TMP"
  mv "$TMP" "$RATE_FILE"
else
  mv "$TMP" "$RATE_FILE"
  echo "Rate limit reached for action '$ACTION_PATH': $ACTION_MAX_UNIQUE unique agents/hr" >&2
  exit 7
fi

# ---- Execute: pipe ORIGINAL payload to Python; tee to action log if set ----
TARGET="$BASE_DIR/$ACTION_PATH"
[[ -f "$TARGET" ]] || { echo "Script not found: $TARGET" >&2; exit 2; }
command -v "$PYTHON_BIN" >/dev/null 2>&1 || { echo "Python not found" >&2; exit 3; }

if [[ -n "$ACTION_LOG" ]]; then
  mkdir -p "$(dirname "$ACTION_LOG")" || true
  echo "$INPUT_JSON" | "$PYTHON_BIN" "$TARGET" 2>&1 | tee -a "$ACTION_LOG"
else
  echo "$INPUT_JSON" | "$PYTHON_BIN" "$TARGET"
fi

