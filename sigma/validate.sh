#!/usr/bin/env bash
# Lint the EmpowerU Sigma rules and test-convert every rule to Splunk SPL
# (with and without sigma/pipelines/splunk_linux_raw.yml), Elasticsearch ES|QL,
# and, for non-correlation rules, Elasticsearch Lucene. Read-only.
# Requires: pip install -r sigma/requirements.txt
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== structure, metadata, mapping table, sample logs"
python3 "${here}/tests/test_sigma_pack.py"

echo "== sigma check (fail on errors and validation issues)"
sigma check --fail-on-error --fail-on-issues "${here}/rules"

echo "== conversions (base rules first; see tests/convert_all.py)"
python3 "${here}/tests/convert_all.py"

echo "OK: Sigma rules linted and converted."
