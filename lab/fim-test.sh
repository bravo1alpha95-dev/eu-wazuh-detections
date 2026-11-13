#!/usr/bin/env bash
# Run the FIM test for EmpowerU rules 100020 and 100021 against a running
# wazuh-lab manager + agent. Defensive lab use only.
#
# Usage (from the lab/ directory, after "docker compose up -d" and after
# the agent shows as Active):
#   ./fim-test.sh
#   sudo ./fim-test.sh    # if docker requires sudo
set -euo pipefail

DC=(docker)
if ! docker info >/dev/null 2>&1; then
  if sudo docker info >/dev/null 2>&1; then
    DC=(sudo docker)
  else
    echo "Cannot talk to Docker. Is Docker Engine running, and do you need sudo?" >&2
    exit 1
  fi
fi

MANAGER=wazuh-lab-manager
AGENT=wazuh-lab-agent

if ! "${DC[@]}" exec "$MANAGER" /var/ossec/bin/agent_control -l | grep -q 'wazuh-lab-agent.*Active'; then
  echo "Agent is not Active yet. Wait until this lists wazuh-lab-agent as Active:" >&2
  echo "  ${DC[*]} exec $MANAGER /var/ossec/bin/agent_control -l" >&2
  exit 1
fi

# A brand-new file produces default rule 554 ("File added"), which 100020
# and 100021 do not match. They are children of 550 ("Integrity checksum
# changed") and only fire when a file already in the baseline is modified.
# If sshd_config is missing, create it, let a scan run, then modify it.
if ! "${DC[@]}" exec "$AGENT" test -f /etc/ssh/sshd_config; then
  echo "Creating /etc/ssh/sshd_config so it can enter the FIM baseline."
  "${DC[@]}" exec "$AGENT" bash -c 'mkdir -p /etc/ssh; echo "# EmpowerU FIM lab baseline" > /etc/ssh/sshd_config'
  echo "Requesting a syscheck scan, then waiting 20 seconds..."
  "${DC[@]}" exec "$MANAGER" /var/ossec/bin/agent_control -r -u 001 >/dev/null
  sleep 20
fi

TOKEN="EU-FIM-TEST-$(date +%Y%m%d%H%M%S)"
echo "Test token: $TOKEN"
echo "Modifying /usr/bin/ls (mtime only; contents are left alone) and appending a comment to /etc/ssh/sshd_config."

"${DC[@]}" exec "$AGENT" touch /usr/bin/ls
"${DC[@]}" exec "$AGENT" bash -c "echo '# $TOKEN lab FIM test, safe comment only' >> /etc/ssh/sshd_config"

echo "Requested a backup scheduled scan as well (realtime should already have fired)."
"${DC[@]}" exec "$MANAGER" /var/ossec/bin/agent_control -r -u 001 >/dev/null

echo "Waiting for alerts..."
found_020=0
found_021=0
for i in 1 2 3 4 5 6 7 8 9 10 12 15 18 20; do
  result="$("${DC[@]}" exec "$MANAGER" python3 -c '
import json
ids=set(); paths={}
with open("/var/ossec/logs/alerts/alerts.json") as f:
    for line in f:
        if not line.strip():
            continue
        a=json.loads(line)
        rid=str(a.get("rule",{}).get("id"))
        path=(a.get("syscheck") or {}).get("path","")
        if rid in {"550","554","100020","100021"}:
            ids.add(rid)
            paths.setdefault(rid, []).append(path)
print("ids=" + ",".join(sorted(ids)))
print("paths=" + json.dumps(paths))
')"
  echo "  check $i: $result"
  case "$result" in
    *100020*) found_020=1 ;;
  esac
  case "$result" in
    *100021*) found_021=1 ;;
  esac
  if [ "$found_020" -eq 1 ] && [ "$found_021" -eq 1 ]; then
    echo
    echo "Both rules fired. Leaf alerts (parent 550 is not the leaf once a child matches):"
    "${DC[@]}" exec "$MANAGER" python3 -c '
import json
with open("/var/ossec/logs/alerts/alerts.json") as f:
    for line in f:
        if not line.strip():
            continue
        a=json.loads(line)
        rid=str(a.get("rule",{}).get("id"))
        if rid in {"100020","100021"}:
            s=a.get("syscheck") or {}
            print("---")
            print("rule.id:", rid)
            print("rule.level:", a.get("rule",{}).get("level"))
            print("rule.description:", a.get("rule",{}).get("description"))
            print("timestamp:", a.get("timestamp"))
            print("syscheck.path:", s.get("path"))
            print("syscheck.event:", s.get("event"))
            print("syscheck.mode:", s.get("mode"))
            print("syscheck.changed_attributes:", s.get("changed_attributes"))
            print("full_log:")
            print(a.get("full_log"))
'
    exit 0
  fi
  sleep 4
done

echo "Did not see both 100020 and 100021. Dumping recent FIM-related alerts (including 550 and 554):" >&2
"${DC[@]}" exec "$MANAGER" python3 -c '
import json
with open("/var/ossec/logs/alerts/alerts.json") as f:
    for line in f:
        if not line.strip():
            continue
        a=json.loads(line)
        rid=str(a.get("rule",{}).get("id"))
        path=(a.get("syscheck") or {}).get("path","")
        if rid in {"550","553","554","100020","100021"} or "sshd" in path or path.endswith("/ls"):
            print(rid, a.get("rule",{}).get("description"), path, (a.get("syscheck") or {}).get("event"))
'
exit 1
