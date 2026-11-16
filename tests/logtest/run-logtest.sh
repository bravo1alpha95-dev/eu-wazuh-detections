#!/usr/bin/env bash
# Run the EmpowerU rule pack through wazuh-logtest on a throwaway official
# Wazuh manager container, and check each synthetic sample produces the
# expected rule IDs (tests/logtest/expected.tsv).
#
# Defensive test only: it starts ONE local container from the official
# wazuh/wazuh-manager image, feeds it the synthetic samples in
# tests/samples/ (RFC 5737 documentation IPs), and removes that container
# when done. Nothing is sent to any other host.
#
# Usage:
#   tests/logtest/run-logtest.sh                       # 4.14.10
#   EU_WAZUH_VERSION=4.12.0 tests/logtest/run-logtest.sh
#
# Environment:
#   EU_WAZUH_VERSION   manager image tag (default 4.14.10)
#   EU_WAZUH_IMAGE     image repository (default wazuh/wazuh-manager)
#   EU_LOGTEST_TIMEOUT seconds to wait for "Logtest started" (default 420)
#   EU_LOGTEST_REPORT  optional path for a TSV report (sample, result, ids)
#   EU_LOGTEST_KEEP    set to yes to leave the container running for debugging
#
# Exit status: 0 when every sample matched, 1 when any did not, 2 on setup error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EU_WAZUH_VERSION="${EU_WAZUH_VERSION:-4.14.10}"
EU_WAZUH_IMAGE="${EU_WAZUH_IMAGE:-wazuh/wazuh-manager}"
EU_LOGTEST_TIMEOUT="${EU_LOGTEST_TIMEOUT:-420}"
[[ "$EU_LOGTEST_TIMEOUT" =~ ^[0-9]{1,5}$ ]] || { echo "EU_LOGTEST_TIMEOUT must be a whole number of seconds." >&2; exit 2; }
EU_LOGTEST_REPORT="${EU_LOGTEST_REPORT:-}"
EU_LOGTEST_KEEP="${EU_LOGTEST_KEEP:-no}"
EXPECTED="$ROOT/tests/logtest/expected.tsv"
SAMPLES="$ROOT/tests/samples"

if [[ ! "$EU_WAZUH_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "EU_WAZUH_VERSION must look like 4.14.10 (got: $EU_WAZUH_VERSION)" >&2
  exit 2
fi

DC=(docker)
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then
    DC=(sudo -n docker)
  else
    echo "Cannot talk to Docker. Is it running, and do you need sudo?" >&2
    exit 2
  fi
fi

# Pick a fixed-offset zone whose local hour is 02 right now, so the
# 00:00-05:00 <time> window in 100012 and 100018 is open for ~3 hours.
utc_h=$((10#$(date -u +%H)))
off=$(( (2 - utc_h + 24) % 24 ))
if (( off > 14 )); then off=$(( off - 24 )); fi
if (( off == 0 )); then TZ_IN_WINDOW="Etc/GMT"
elif (( off > 0 )); then TZ_IN_WINDOW="Etc/GMT-$off"   # POSIX sign is inverted
else TZ_IN_WINDOW="Etc/GMT+$(( -off ))"; fi

NAME="eu-logtest-${EU_WAZUH_VERSION//./-}-$$"
cleanup() {
  if [[ "$EU_LOGTEST_KEEP" != "yes" ]]; then
    "${DC[@]}" rm -f "$NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== wazuh-logtest matrix entry: $EU_WAZUH_IMAGE:$EU_WAZUH_VERSION (manager zone $TZ_IN_WINDOW)"
# Files go in through /wazuh-config-mount/, the official images' documented
# hook: /init copies it over /var/ossec/ after preparing the data volume.
# Bind-mounting straight into /var/ossec/etc/rules/ breaks older images
# (4.10.1 then skips installing /var/ossec/etc and never starts analysisd).
#
# How the zone is set matters too. wazuh-analysisd runs chrooted in
# /var/ossec and evaluates <time> with /var/ossec/etc/localtime, which the
# images ship as UTC. On 4.12.0, 4.13.1 and 4.14.0, -e TZ=<zone> left <time>
# rules on UTC (4.14.10 honors it). So TZ is NOT passed; the zone file is
# copied into the chroot through the same hook, which works on every
# version in the matrix.
# shellcheck disable=SC2016  # $EU_LOGTEST_ZONE expands inside the container
"${DC[@]}" run -d --name "$NAME" -e "EU_LOGTEST_ZONE=$TZ_IN_WINDOW" \
  --entrypoint /bin/sh \
  -v "$ROOT/rules/eu_ec_detect_rules.xml:/wazuh-config-mount/etc/rules/eu_ec_detect_rules.xml:ro" \
  -v "$ROOT/decoders/eu_ec_detect_decoders.xml:/wazuh-config-mount/etc/decoders/eu_ec_detect_decoders.xml:ro" \
  "$EU_WAZUH_IMAGE:$EU_WAZUH_VERSION" \
  -c 'cp "/usr/share/zoneinfo/$EU_LOGTEST_ZONE" /wazuh-config-mount/etc/localtime && ln -sf "/usr/share/zoneinfo/$EU_LOGTEST_ZONE" /etc/localtime && exec /init' >/dev/null

# Confirm the pack really is in place (the copy happens during /init).
echo "Waiting up to ${EU_LOGTEST_TIMEOUT}s for wazuh-analysisd to report 'Logtest started'..."
deadline=$(( SECONDS + EU_LOGTEST_TIMEOUT ))
until "${DC[@]}" exec "$NAME" grep -q "Logtest started" /var/ossec/logs/ossec.log 2>/dev/null; do
  if (( SECONDS > deadline )); then
    echo "Timed out. Last ossec.log lines:" >&2
    "${DC[@]}" exec "$NAME" tail -n 40 /var/ossec/logs/ossec.log >&2 || "${DC[@]}" logs --tail 40 "$NAME" >&2 || true
    exit 2
  fi
  if [[ "$("${DC[@]}" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]]; then
    echo "Manager container exited. Logs:" >&2
    "${DC[@]}" logs --tail 60 "$NAME" >&2 || true
    exit 2
  fi
  sleep 3
done

if ! "${DC[@]}" exec "$NAME" test -f /var/ossec/etc/rules/eu_ec_detect_rules.xml; then
  echo "eu_ec_detect_rules.xml is not in /var/ossec/etc/rules/ after start-up." >&2
  exit 2
fi
version_json="$("${DC[@]}" exec "$NAME" cat /var/ossec/VERSION.json 2>/dev/null || true)"
[[ -n "$version_json" ]] && echo "VERSION.json: $(echo "$version_json" | tr -d '\n ')"

# Any rule or decoder load problem that mentions our files is a failure.
load_errors="$("${DC[@]}" exec "$NAME" grep -E "(ERROR|CRITICAL).*(eu_ec_detect|rule|decoder)" /var/ossec/logs/ossec.log 2>/dev/null || true)"
if [[ -n "$load_errors" ]]; then
  echo "Rule or decoder load errors in ossec.log:" >&2
  echo "$load_errors" >&2
  exit 1
fi
rules_enabled="$("${DC[@]}" exec "$NAME" grep -oE "Total rules enabled: .?[0-9]+.?" /var/ossec/logs/ossec.log 2>/dev/null | tail -n1 || true)"
echo "${rules_enabled:-Total rules enabled: (not logged)}"

[[ -n "$EU_LOGTEST_REPORT" ]] && printf 'version\tsample\tresult\tids_seen\n' > "$EU_LOGTEST_REPORT"

pass=0; fail=0
while IFS=$'\t' read -r sample must mustnot; do
  [[ -z "$sample" || "$sample" == \#* ]] && continue
  if [[ ! -f "$SAMPLES/$sample" ]]; then
    echo "FAIL $sample: sample file missing"; fail=$((fail + 1)); continue
  fi
  out="$("${DC[@]}" exec -i "$NAME" /var/ossec/bin/wazuh-logtest < "$SAMPLES/$sample" 2>&1 || true)"
  # Rule IDs appear as "id: 'NNNN'" under "Phase 3: Completed filtering (rules)".
  ids="$(printf '%s\n' "$out" | sed -n "s/^[[:space:]]*id: '\([0-9][0-9]*\)'.*/\1/p" | sort -un | paste -sd, -)"
  ok=1; why=""
  IFS=, read -ra want <<<"$must"
  for id in "${want[@]}"; do
    [[ "$id" == "-" || -z "$id" ]] && continue
    [[ ",$ids," == *",$id,"* ]] || { ok=0; why+=" missing $id"; }
  done
  IFS=, read -ra deny <<<"${mustnot:--}"
  for id in "${deny[@]}"; do
    [[ "$id" == "-" || -z "$id" ]] && continue
    [[ ",$ids," == *",$id,"* ]] && { ok=0; why+=" unexpected $id"; }
  done
  if (( ok )); then
    echo "PASS $sample -> ${ids:-none}"; pass=$((pass + 1)); res=PASS
  else
    echo "FAIL $sample -> ${ids:-none} (${why# })"; fail=$((fail + 1)); res=FAIL
  fi
  [[ -n "$EU_LOGTEST_REPORT" ]] && printf '%s\t%s\t%s\t%s\n' "$EU_WAZUH_VERSION" "$sample" "$res" "${ids:-none}" >> "$EU_LOGTEST_REPORT"
done < "$EXPECTED"

echo "== $EU_WAZUH_VERSION: $pass passed, $fail failed"
(( fail == 0 ))
