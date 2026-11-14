#!/usr/bin/env bash
# 8 synthetic SSH "Invalid user" attempts from one documentation IP, then an
# accepted password from the same IP. Expected: 5710 x8 -> 5712 -> 100016,
# then 5715 -> 100017 (same source IP within 180s).
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
ip="${EU_SIM_SSH_SRC_IP:-198.51.100.20}"
case "$ip" in 192.0.2.*|198.51.100.*|203.0.113.*) ;; *) echo "EU_SIM_SSH_SRC_IP must be RFC 5737." >&2; exit 2 ;; esac
sim_banner "ssh-burst: 8 invalid-user attempts from $ip, then an accepted login (expect 100016, 100017)"
for i in 1 2 3 4 5 6 7 8; do
  sim_syslog "sshd[$((4200 + i))]" "Invalid user eu-sim-guest$i from $ip port $((50000 + i))"
  sim_pause 0.3
done
sim_pause 2
sim_syslog "sshd[4220]" "Accepted password for eu-sim-bob from $ip port 50100 ssh2"
