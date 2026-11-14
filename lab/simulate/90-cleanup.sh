#!/usr/bin/env bash
# Remove simulation leftovers from the agent container: EU-SIM comment lines
# in sshd_config, /etc/sudoers.d/eu-sim, and the synthetic log file. These
# edits are themselves FIM events (expect 550/553 and possibly 100021).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
sim_banner "cleanup: remove $EU_SIM_TAG lines and files from $EU_SIM_AGENT"
sim_agent_cmd "if [ -f /etc/ssh/sshd_config ]; then sed -i '/$EU_SIM_TAG/d' /etc/ssh/sshd_config; fi"
sim_agent_cmd "rm -f /etc/sudoers.d/eu-sim"
sim_agent_cmd ": > '$EU_SIM_LOG' 2>/dev/null || true"
