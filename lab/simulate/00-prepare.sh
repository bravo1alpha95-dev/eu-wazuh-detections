#!/usr/bin/env bash
# Create the lab-only monitored log file inside the agent container and
# confirm the agent has the shared config that watches it
# (lab/manager/agent.conf adds a <localfile> for /var/log/eu-sim/auth.log).
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
sim_gate
sim_banner "prepare: monitored file $EU_SIM_LOG in $EU_SIM_AGENT"
sim_agent_cmd "mkdir -p /var/log/eu-sim && touch '$EU_SIM_LOG' && chmod 640 '$EU_SIM_LOG'"
if "${DC[@]}" exec "$EU_SIM_AGENT" grep -q "$EU_SIM_LOG" /var/ossec/etc/shared/agent.conf 2>/dev/null; then
  echo "  agent shared config already monitors $EU_SIM_LOG"
else
  echo "  WARNING: the agent's shared config does not list $EU_SIM_LOG yet." >&2
  echo "  Make sure lab/manager/agent.conf is mounted on the manager (lab/docker-compose.yml does this)," >&2
  echo "  then wait ~1 minute for the agent to pull it, or restart the agent container." >&2
fi
