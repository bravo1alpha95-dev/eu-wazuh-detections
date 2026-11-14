#!/usr/bin/env bash
# One synthetic successful SSH login as root. Expected: 5715 -> 100013.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
ip="${EU_SIM_ROOT_SRC_IP:-192.0.2.30}"
case "$ip" in 192.0.2.*|198.51.100.*|203.0.113.*) ;; *) echo "EU_SIM_ROOT_SRC_IP must be RFC 5737." >&2; exit 2 ;; esac
sim_banner "root-ssh: accepted SSH login as root from $ip (expect 100013)"
sim_syslog "sshd[4300]" "Accepted publickey for root from $ip port 50300 ssh2"
