#!/usr/bin/env bash
# Synthetic Wazuh process-monitoring output that lists a netcat listener.
# No listener is opened. Expected: 530 -> 100002.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
sim_banner "listener: synthetic 'ps aux' command output naming nc -l (expect 100002)"
sim_raw "ossec: output: 'ps aux': root 4500 0.0 0.0 nc -l 4444 $EU_SIM_TAG"
