#!/usr/bin/env bash
# Lint the EmpowerU Sigma rules and test-convert every rule to Splunk SPL,
# Elasticsearch ES|QL, and (for non-correlation rules) Elasticsearch Lucene.
# Read-only: writes converted queries to a temporary directory and removes it.
# Requires: pip install -r sigma/requirements.txt
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rules="${here}/rules"
out="$(mktemp -d)"
trap 'rm -rf "${out}"' EXIT

python3 "${here}/tests/test_sigma_pack.py"

echo "== sigma check (fail on errors and validation issues)"
sigma check --fail-on-error --fail-on-issues "${rules}"

total="$(find "${rules}" -name '*.yml' | wc -l)"
plain=()
while IFS= read -r f; do
  grep -q '^correlation:' "${f}" || plain+=("${f}")
done < <(find "${rules}" -name '*.yml' | sort)

convert() { # target, label, expected-count, inputs...
  local target="$1" label="$2" want="$3"; shift 3
  local dir="${out}/${label}"
  mkdir -p "${dir}"
  sigma convert -t "${target}" --without-pipeline --fail-unsupported \
    -od "${dir}" -ot '{stem}.txt' "$@" >/dev/null
  local got
  got="$(find "${dir}" -type f -size +0 | wc -l)"
  echo "== ${label}: ${got}/${want} rules converted"
  [ "${got}" -eq "${want}" ] || { echo "FAIL: expected ${want} conversions for ${label}" >&2; exit 1; }
}

convert splunk splunk "${total}" "${rules}"
convert esql esql "${total}" "${rules}"
convert lucene lucene "${#plain[@]}" "${plain[@]}"

echo "== splunk with sigma/pipelines/splunk_linux_raw.yml"
mkdir -p "${out}/splunk-raw"
sigma convert -t splunk -p "${here}/pipelines/splunk_linux_raw.yml" --fail-unsupported \
  -od "${out}/splunk-raw" -ot '{stem}.txt' "${rules}" >/dev/null
grep -q '_raw=' "${out}/splunk-raw/eu_100013_ssh_root_login.txt"

echo "OK: ${total} Sigma rules linted; Splunk ${total}, ES|QL ${total}, Lucene ${#plain[@]} (correlations skipped: Lucene has no correlation support)."
