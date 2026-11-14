#!/usr/bin/env bash
# EmpowerU attack-simulation runner. Runs every scenario against the lab
# agent container, then reads the manager's alerts.json and reports which
# rule IDs fired. Defensive lab use only; see lib.sh for the safety model.
#
#   ./simulate/run-all.sh                 # dry run: prints every step, changes nothing
#   CONFIRM=yes ./simulate/run-all.sh     # act on wazuh-lab-agent and check alerts
#
# Environment:
#   CONFIRM=yes            required to change anything
#   EU_SIM_WAIT            seconds to wait for alerts after the last scenario (default 90)
#   EU_SIM_REPORT_DIR      where reports go (default lab/simulate/results; 700/600)
#   EU_SIM_ONLY            space-separated scenario names to run (default: all)
#                          names: root-ssh offhours listener user-sudo fim pam-burst ssh-burst
#
# Exit status: 0 if every expected rule fired, 1 if any did not, 2/3 on setup or scope errors.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$HERE/lib.sh"
umask 077

EU_SIM_WAIT="${EU_SIM_WAIT:-90}"
EU_SIM_REPORT_DIR="${EU_SIM_REPORT_DIR:-$HERE/results}"
EU_SIM_ONLY="${EU_SIM_ONLY:-}"
ALERTS=/var/ossec/logs/alerts/alerts.json

# Order matters: 100011 correlates ANY PAM success within 180s after 100010
# (no same_source_ip, because PAM "session opened" lines carry no rhost), so
# the PAM burst runs after the scenarios that log PAM successes.
SCENARIOS=(root-ssh offhours listener user-sudo fim pam-burst ssh-burst)
declare -A SCRIPT=(
  [root-ssh]=10-root-ssh.sh [offhours]=20-offhours.sh [listener]=30-listener.sh
  [user-sudo]=40-user-sudo.sh [fim]=50-fim.sh [pam-burst]=60-pam-burst.sh [ssh-burst]=70-ssh-burst.sh
)

sim_gate
hour="$("${DC[@]}" exec "$EU_SIM_MANAGER" date +%H)"
in_window=0; (( 10#$hour < 5 )) && in_window=1
declare -A EXPECT=(
  [root-ssh]="100013"
  [listener]="100002"
  [user-sudo]="5902 5402|5403 100021"   # 5403 = first sudo by that user; 554 (file added) only on the first run
  [fim]="100020 100021"
  [pam-burst]="5503 100010 100011"
  [ssh-burst]="5710 100016 100017"
)
if (( in_window )); then EXPECT[offhours]="100012 100018"; else EXPECT[offhours]="5501 5715"; fi

selected=()
for s in "${SCENARIOS[@]}"; do
  if [[ -z "$EU_SIM_ONLY" || " $EU_SIM_ONLY " == *" $s "* ]]; then selected+=("$s"); fi
done
(( ${#selected[@]} )) || { echo "EU_SIM_ONLY matched no scenario." >&2; exit 2; }

echo "Target agent: $EU_SIM_AGENT (compose project $EU_SIM_PROJECT); manager: $EU_SIM_MANAGER (local hour $hour)"
if (( ! in_window )); then
  echo "Note: manager clock is outside 00:00-05:00, so off-hours rules 100012/100018 are expected NOT to fire now."
fi

if ! is_live; then
  for s in "${selected[@]}"; do
    CONFIRM=no "$HERE/${SCRIPT[$s]}"
    echo "   expect: ${EXPECT[$s]}"
  done
  echo
  echo "DRY RUN complete. Nothing was changed. Re-run with CONFIRM=yes to act on $EU_SIM_AGENT."
  exit 0
fi

"$HERE/00-prepare.sh"
# Byte offset into alerts.json, so we only read alerts produced by this run.
offset="$("${DC[@]}" exec "$EU_SIM_MANAGER" stat -c %s "$ALERTS" 2>/dev/null || echo 0)"
started="$(date '+%Y-%m-%d %H:%M:%S %Z')"
for s in "${selected[@]}"; do
  "$HERE/${SCRIPT[$s]}"
  sleep 3
done

want=()
for s in "${selected[@]}"; do read -ra ids <<<"${EXPECT[$s]}"; want+=("${ids[@]}"); done

collect() {
  "${DC[@]}" exec -i "$EU_SIM_MANAGER" /var/ossec/framework/python/bin/python3 - "$ALERTS" "$offset" "$EU_SIM_AGENT" <<'PY'
import json, sys
path, offset, agent = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(path, "rb") as f:
    f.seek(0, 2)
    if f.tell() < offset:      # rotated at midnight; read the new file from the start
        offset = 0
    f.seek(offset)
    data = f.read().decode("utf-8", "replace")
out = []
for line in data.splitlines():
    if not line.strip():
        continue
    try:
        a = json.loads(line)
    except ValueError:
        continue
    if (a.get("agent") or {}).get("name") != agent:
        continue
    r = a.get("rule") or {}
    d = a.get("data") or {}
    out.append({
        "timestamp": a.get("timestamp"),
        "rule_id": str(r.get("id")),
        "level": r.get("level"),
        "description": r.get("description"),
        "groups": r.get("groups"),
        "location": a.get("location"),
        "srcip": d.get("srcip"),
        "user": d.get("dstuser") or d.get("srcuser"),
        "syscheck_path": (a.get("syscheck") or {}).get("path"),
        "syscheck_event": (a.get("syscheck") or {}).get("event"),
    })
print(json.dumps(out))
PY
}

echo "Waiting up to ${EU_SIM_WAIT}s for alerts ..."
deadline=$(( SECONDS + EU_SIM_WAIT ))
while :; do
  alerts="$(collect)"
  missing="$(python3 - "$alerts" "${want[@]}" <<'PY'
import json, sys
seen = {a["rule_id"] for a in json.loads(sys.argv[1])}
# "A|B" means either rule ID satisfies the expectation.
print(" ".join(sorted({w for w in sys.argv[2:] if not seen.intersection(w.split("|"))})))
PY
)"
  [[ -z "$missing" ]] && break
  (( SECONDS > deadline )) && break
  sleep 5
done

mkdir -p "$EU_SIM_REPORT_DIR"; chmod 700 "$EU_SIM_REPORT_DIR"
stamp="$(date +%Y%m%d-%H%M%S)"
report="$EU_SIM_REPORT_DIR/simulation-$stamp.md"
raw="$EU_SIM_REPORT_DIR/simulation-$stamp.json"
printf '%s\n' "$alerts" > "$raw"
expect_lines=""
for s in "${selected[@]}"; do expect_lines+="$s=${EXPECT[$s]};"; done
python3 - "$alerts" "$started" "$hour" "$expect_lines" "$EU_SIM_AGENT" > "$report" <<'PY'
import json, sys
from collections import Counter, OrderedDict
alerts, started, hour, expect, agent = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
counts = Counter(a["rule_id"] for a in alerts)
desc = {}
for a in alerts:
    desc.setdefault(a["rule_id"], a["description"])
print(f"# EmpowerU attack simulation — {started}\n")
print(f"Target agent container: `{agent}`. Manager local hour at start: {hour}.\n")
print("| Scenario | Expected rule IDs | Fired | Missing | Result |")
print("|---|---|---|---|---|")
allok = True
for item in filter(None, expect.split(";")):
    name, ids = item.split("=", 1)
    ids = ids.split()
    hit = lambda i: any(counts.get(x) for x in i.split("|"))
    fired = ["/".join(x for x in i.split("|") if counts.get(x)) for i in ids if hit(i)]
    miss = [i.replace("|", " or ") for i in ids if not hit(i)]
    allok &= not miss
    print(f"| {name} | {', '.join(i.replace('|', ' or ') for i in ids)} | {', '.join(fired) or '-'} | {', '.join(miss) or '-'} | {'PASS' if not miss else 'FAIL'} |")
print("\n## All rule IDs seen from this agent during the run\n")
print("| Rule ID | Count | Description |")
print("|---|---|---|")
for rid in sorted(counts, key=lambda x: int(x) if x.isdigit() else 0):
    mark = " **(EmpowerU)**" if rid.startswith("100") else ""
    print(f"| {rid} | {counts[rid]} | {desc[rid]}{mark} |")
print(f"\nOverall: {'PASS' if allok else 'FAIL'}")
PY
chmod 600 "$report" "$raw"
cat "$report"
echo
echo "Report: $report"
echo "Alerts (selected fields only): $raw"
grep -q '^Overall: PASS' "$report"
