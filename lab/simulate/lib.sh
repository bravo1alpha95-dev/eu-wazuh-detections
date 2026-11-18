#!/usr/bin/env bash
# Shared helpers for the EmpowerU attack-simulation lab. Sourced, not run.
#
# Safety model (defensive lab use only):
#   * Dry-run by default. Nothing changes unless CONFIRM=yes.
#   * Scope gate: the ONLY target is the lab agent container. Before any
#     change, the container must exist, be running, and carry the Docker
#     Compose label com.docker.compose.project=$EU_SIM_PROJECT
#     (default wazuh-lab). There is no option to point at a host, IP, or URL.
#   * No network traffic is generated toward anything. Authentication and
#     process events are SYNTHETIC log lines (RFC 5737 documentation IPs)
#     appended to a lab-only file the agent monitors. File-integrity events
#     are real, harmless edits inside the agent container (mtime touch and
#     comment lines tagged EU-SIM).
# shellcheck disable=SC2034  # variables are used by the scripts that source this

EU_SIM_AGENT="${EU_SIM_AGENT:-wazuh-lab-agent}"
EU_SIM_MANAGER="${EU_SIM_MANAGER:-wazuh-lab-manager}"
EU_SIM_PROJECT="${EU_SIM_PROJECT:-wazuh-lab}"
EU_SIM_LOG="${EU_SIM_LOG:-/var/log/eu-sim/auth.log}"
EU_SIM_SRC_IP="${EU_SIM_SRC_IP:-203.0.113.10}"
EU_SIM_TAG="${EU_SIM_TAG:-EU-SIM}"
CONFIRM="${CONFIRM:-no}"

# Only documentation ranges (RFC 5737) are allowed as synthetic sources.
case "$EU_SIM_SRC_IP" in
  192.0.2.*|198.51.100.*|203.0.113.*) ;;
  *) echo "EU_SIM_SRC_IP must be in an RFC 5737 documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)." >&2; exit 2 ;;
esac
# EU_SIM_LOG and EU_SIM_TAG are interpolated into shell commands and a sed
# expression run as root inside the agent container, so accept a conservative
# charset only. ".." is rejected so the path cannot climb out of /var/log/eu-sim/.
if [[ ! "$EU_SIM_LOG" =~ ^/var/log/eu-sim/[A-Za-z0-9._/-]+$ || "$EU_SIM_LOG" == *..* ]]; then
  echo "EU_SIM_LOG must live under /var/log/eu-sim/ inside the agent container (letters, digits, . _ - / only; no ..)." >&2; exit 2
fi
if [[ ! "$EU_SIM_TAG" =~ ^[A-Za-z0-9_-]{1,32}$ ]]; then
  echo "EU_SIM_TAG must be 1-32 letters, digits, _ or - (it is used in shell and sed inside the container)." >&2; exit 2
fi

sim_docker_init() {
  if docker info >/dev/null 2>&1; then DC=(docker)
  elif sudo -n docker info >/dev/null 2>&1; then DC=(sudo -n docker)
  else echo "Cannot talk to Docker (is it running? do you need sudo?)." >&2; exit 2; fi
}

is_live() { [[ "$CONFIRM" == "yes" ]]; }

# Scope gate. Exits unless the target is the running lab agent container.
sim_gate() {
  sim_docker_init
  local c running project
  for c in "$EU_SIM_AGENT" "$EU_SIM_MANAGER"; do
    running="$("${DC[@]}" inspect -f '{{.State.Running}}' "$c" 2>/dev/null || true)"
    project="$("${DC[@]}" inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$c" 2>/dev/null || true)"
    if [[ "$running" != "true" ]]; then
      echo "Scope gate: container '$c' is not running. Start the lab first (cd lab && docker compose up -d)." >&2; exit 3
    fi
    if [[ "$project" != "$EU_SIM_PROJECT" ]]; then
      echo "Scope gate: '$c' is not part of compose project '$EU_SIM_PROJECT' (found '${project:-none}'). Refusing." >&2; exit 3
    fi
  done
}

agent_exec() { "${DC[@]}" exec -i "$EU_SIM_AGENT" "$@"; }

# Print (dry run) or append (CONFIRM=yes) one syslog-style line to the
# monitored lab file inside the agent container. $1 = program[pid], $2 = message.
sim_syslog() {
  local line
  line="$(date '+%b %e %H:%M:%S') eu-sim-host $1: $2"
  if is_live; then
    # shellcheck disable=SC2016  # $1 expands inside the container shell
    printf '%s\n' "$line" | agent_exec sh -c 'mkdir -p "$(dirname "$1")" && cat >> "$1"' sh "$EU_SIM_LOG"
  else
    echo "  would append: $line"
  fi
}

# Same, but the raw line has no syslog header (Wazuh command-output format).
sim_raw() {
  if is_live; then
    # shellcheck disable=SC2016  # $1 expands inside the container shell
    printf '%s\n' "$1" | agent_exec sh -c 'cat >> "$1"' sh "$EU_SIM_LOG"
  else
    echo "  would append: $1"
  fi
}

# Run a command inside the agent container (or print it in dry run).
sim_agent_cmd() {
  if is_live; then
    agent_exec sh -c "$1"
  else
    echo "  would run in $EU_SIM_AGENT: $1"
  fi
}

sim_pause() { if is_live; then sleep "${1:-1}"; fi; }

sim_banner() {
  echo "== $1"
  is_live || echo "   (dry run; set CONFIRM=yes to act on container $EU_SIM_AGENT)"
}
