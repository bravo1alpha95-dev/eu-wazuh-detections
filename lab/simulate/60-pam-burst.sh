#!/usr/bin/env bash
# 8 synthetic PAM authentication failures from one documentation IP, then a
# PAM session opened. Expected: 5503 x8 -> 5551 -> 100010, then 100011.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
sim_banner "pam-burst: 8 PAM failures from $EU_SIM_SRC_IP, then a PAM success (expect 100010, 100011)"
for i in 1 2 3 4 5 6 7 8; do
  sim_syslog "sshd[$((4100 + i))]" "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=$EU_SIM_SRC_IP  user=eu-sim-alice"
  sim_pause 0.3
done
sim_pause 2
sim_syslog "sshd[4120]" "pam_unix(sshd:session): session opened for user eu-sim-alice by (uid=0)"
