###############################################################################
# smartpt-integrations  —  High-level Flow (for file header comment)
#
# Goal: One Active Response handles many rules; dispatcher routes to per-action
# Python scripts, with per-action rate limits, filters, and logging.
#
#                             ┌─────────────────────────────┐
#                             │        Wazuh Engine         │
#                             │  (rule triggers ActiveResp) │
#                             └──────────────┬──────────────┘
#                                            │ JSON (stdin)
#                                 /var/ossec/active-response/bin/integrations
#                                            │
#                         ┌──────────────────▼──────────────────┐
#                         │        Dispatcher (bash)            │
#                         │ 1) Read full STDIN → INPUT_JSON     │
#                         │ 2) Regex extract:                   │
#                         │    • rule_id  from "rule":{...}     │
#                         │    • agent_id from "agent":{...}    │
#                         │    • agent_name from "agent":{...}  │
#                         └───────────────┬─────────────────────┘
#                                         │
#                                         │
#                          ┌──────────────▼──────────────┐
#                          │  Load actions.conf (lines)  │
#                          │  action=py/xxx.py;          │
#                          │  rules=60154,60158;         │
#                          │  enabled=true;              │
#                          │  log=/var/log/...;          │
#                          │  max_unique_per_hour=8;     │
#                          │  exclude_agents=a,b,c;      │
#                          │  server_type_pattern="..."  │
#                          └──────────────┬──────────────┘
#                                         │
#                         ┌───────────────▼────────────────┐
#                         │   Match RULE_ID to an action    │
#                         │   (first line whose rules list  │
#                         │    contains RULE_ID)            │
#                         └───────────────┬────────────────┘
#                                         │
#              ┌──────────────────────────┼───────────────────────────┐
#              │                          │                           │
#   enabled?   ▼                          ▼                           ▼
#      NO  ─── skip (exit 0)   exclude_agents hits agent_name?   server_type_pattern
#                                YES ─── skip (exit 0)           present AND NOT matched?
#                                                                YES ─── skip (exit 0)
#              │                          │                           │
#              └───────────────┬──────────┴───────────────┬───────────┘
#                              │                          │
#                              ▼                          ▼
#                  ┌───────────────────┐       ┌────────────────────────┐
#                  │ Per-action rate   │       │ Execute mapped action  │
#                  │ limit (rolling 1h)│       │ Python script          │
#                  │ file: rlimit.<act>│       │                        │
#                  │  • allow N unique │  JSON │  echo "$INPUT_JSON" |  │
#                  │    agent keys/hr  │  ───▶ │  python3 py/xxx.py     │
#                  │  • allow repeats  │       │                        │
#                  │    for same agent │       │  • If `log=` set → tee │
#                  └──────────┬────────┘       │    to that file        │
#                             │                │  • Exit code bubbles   │
#                   limit hit?│                │    back to Wazuh       │
#                     YES ────┴── exit 7       └───────────┬────────────┘
#                                                         │
#                                            ┌────────────▼────────────┐
#                                            │ Return exit code to AR  │
#                                            │ 0 = success/skip        │
#                                            │ 2 = missing/mapping err │
#                                            │ 3 = python not found    │
#                                            │ 5 = rate lock busy      │
#                                            │ 7 = rate limit reached  │
#                                            └─────────────────────────┘
#
# Notes:
# • Regex extraction tolerates non-perfect JSON (pretty or compact).
# • RULE_ID → action mapping lives in actions.conf (one line per action).
# • Per-action overrides: enabled, log path, max_unique_per_hour,
#   exclude_agents (by agent.name), server_type_pattern (regex that MUST match).
# • Rate limit key uses agent_id when available, else agent_name.
# • Only the first matching line in actions.conf is used (top-to-bottom).
###############################################################################
