#!/usr/bin/env bash
# Synthetic non-root PAM and SSH successes. Expected 100012 and 100018 ONLY
# when the MANAGER's local clock is between 00:00 and 05:00 (Wazuh <time>
# uses the manager clock, not the log timestamp). Outside that window the
# defaults 5501 and 5715 fire instead, which is the correct behavior.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
ip="${EU_SIM_OFFHOURS_SRC_IP:-192.0.2.40}"
case "$ip" in 192.0.2.*|198.51.100.*|203.0.113.*) ;; *) echo "EU_SIM_OFFHOURS_SRC_IP must be RFC 5737." >&2; exit 2 ;; esac
hour="$("${DC[@]}" exec "$EU_SIM_MANAGER" date +%H)"
sim_banner "offhours: PAM + SSH success (manager local hour $hour; 100012/100018 expected only if 00-04)"
sim_syslog "sshd[4400]" "pam_unix(sshd:session): session opened for user eu-sim-carol by (uid=0)"
sim_syslog "sshd[4401]" "Accepted password for eu-sim-carol from $ip port 50400 ssh2"
