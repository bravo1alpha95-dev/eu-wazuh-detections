#!/usr/bin/env bash
# Real, harmless file-integrity changes on the agent container:
#   touch /usr/bin/ls (mtime only)             -> 550 -> 100020
#   append a comment to /etc/ssh/sshd_config  -> 550 -> 100021
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
sim_banner "fim: touch /usr/bin/ls and add a comment to /etc/ssh/sshd_config (expect 100020, 100021)"
sim_agent_cmd "test -f /etc/ssh/sshd_config || { echo 'sshd_config missing: run lab/fim-test.sh once to baseline it' >&2; exit 1; }"
sim_agent_cmd "touch /usr/bin/ls"
sim_agent_cmd "printf '# $EU_SIM_TAG %s comment only\n' \"\$(date +%Y%m%d%H%M%S)\" >> /etc/ssh/sshd_config"
