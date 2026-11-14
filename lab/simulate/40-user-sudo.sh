#!/usr/bin/env bash
# New local user and sudo activity.
#   * Synthetic useradd and sudo log lines -> default Wazuh rules 5902
#     (new user added) and 5402 (successful sudo to root). EmpowerU has no
#     custom rule for these; they are shown so the dashboard has context.
#   * A REAL sudo-policy change on the agent: create /etc/sudoers.d/eu-sim
#     (FIM 554, "file added"), wait for it to enter the baseline, then add a
#     comment line (FIM 550 -> EmpowerU 100021). The file only ever holds
#     comments, so it grants nothing.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
sim_banner "user-sudo: synthetic useradd/sudo lines (expect 5902, 5402) + real /etc/sudoers.d/eu-sim edit (expect 554, then 100021)"
sim_syslog "useradd[4600]" "new user: name=eu-sim-user, UID=4600, GID=4600, home=/home/eu-sim-user, shell=/bin/bash, from=/dev/pts/0"
sim_syslog "sudo" "eu-sim-alice : TTY=pts/0 ; PWD=/home/eu-sim-alice ; USER=root ; COMMAND=/usr/bin/id"
sim_agent_cmd "mkdir -p /etc/sudoers.d && chmod 750 /etc/sudoers.d && if [ ! -f /etc/sudoers.d/eu-sim ]; then printf '# $EU_SIM_TAG lab file. Comments only; grants nothing.\n' > /etc/sudoers.d/eu-sim && chmod 440 /etc/sudoers.d/eu-sim; fi"
# Give realtime FIM time to baseline the new file before modifying it.
sim_pause "${EU_SIM_BASELINE_WAIT:-15}"
sim_agent_cmd "printf '# $EU_SIM_TAG %s comment only\n' \"\$(date +%Y%m%d%H%M%S)\" >> /etc/sudoers.d/eu-sim"
