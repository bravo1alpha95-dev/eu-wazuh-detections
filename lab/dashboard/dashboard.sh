#!/usr/bin/env bash
# EmpowerU Wazuh lab — opt-in Wazuh indexer + dashboard, and the starter
# dashboard import. Defensive lab tooling only.
#
# Dry-run by default. Anything that creates files, starts containers, or
# imports saved objects needs CONFIRM=yes. Read-only actions (plan, verify,
# status) never change anything.
#
#   ./dashboard/dashboard.sh plan                 # default; prints the plan
#   CONFIRM=yes ./dashboard/dashboard.sh generate # certs + random passwords only
#   CONFIRM=yes ./dashboard/dashboard.sh up       # generate (if needed) + start
#   CONFIRM=yes ./dashboard/dashboard.sh import   # import the starter dashboard
#   ./dashboard/dashboard.sh verify               # indexer + dashboard checks
#   ./dashboard/dashboard.sh status
#   CONFIRM=yes ./dashboard/dashboard.sh stop     # stop indexer + dashboard only
#
# Environment (all optional):
#   EU_LAB_DIR            directory holding the base docker-compose.yml
#                         (default: the lab/ directory this script lives in)
#   EU_LAB_PROJECT        compose project name (default: wazuh-lab)
#   EU_LAB_GEN_DIR        where generated certs/passwords go
#                         (default: $EU_LAB_DIR/dashboard/.generated, git-ignored)
#   EU_LAB_INDEXER_BIND   host address for port 9200 (default 0.0.0.0; it must be
#                         reachable from containers through host-gateway)
#   EU_LAB_DASHBOARD_BIND host address for port 5601 (default 127.0.0.1)
#
# Secrets: passwords are generated locally with Python's secrets module and
# written ONLY to $EU_LAB_GEN_DIR/credentials.env (mode 600, directory 700).
# This script never prints a password. Read the file yourself to log in.
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_LAB="$(cd "$HERE/.." && pwd)"
EU_LAB_DIR="$(cd "${EU_LAB_DIR:-$REPO_LAB}" && pwd)"
EU_LAB_PROJECT="${EU_LAB_PROJECT:-wazuh-lab}"
EU_LAB_GEN_DIR="${EU_LAB_GEN_DIR:-$EU_LAB_DIR/dashboard/.generated}"
EU_LAB_INDEXER_BIND="${EU_LAB_INDEXER_BIND:-0.0.0.0}"
EU_LAB_DASHBOARD_BIND="${EU_LAB_DASHBOARD_BIND:-127.0.0.1}"
CONFIRM="${CONFIRM:-no}"
OVERLAY="$REPO_LAB/docker-compose.dashboard.yml"
CONFIG_DIR="$HERE/config"
NDJSON="$REPO_LAB/../dashboards/eu-ec-detect-starter.ndjson"
CREDS="$EU_LAB_GEN_DIR/credentials.env"
CERTS="$EU_LAB_GEN_DIR/certs"
INDEXER_IMAGE="wazuh/wazuh-indexer:4.14.10"
EU_IDS=(100002 100010 100011 100012 100013 100016 100017 100018 100020 100021)

die() { echo "ERROR: $*" >&2; exit 1; }
need_confirm() {
  if [[ "$CONFIRM" != "yes" ]]; then
    echo "DRY RUN: would $1"
    echo "Re-run with CONFIRM=yes to do it."
    exit 0
  fi
}

DC=(docker)
docker_init() {
  if docker info >/dev/null 2>&1; then DC=(docker)
  elif sudo -n docker info >/dev/null 2>&1; then DC=(sudo -n docker)
  else die "cannot talk to Docker (is it running? do you need sudo?)"; fi
}
compose() {
  "${DC[@]}" compose -p "$EU_LAB_PROJECT" --project-directory "$EU_LAB_DIR" \
    -f "$EU_LAB_DIR/docker-compose.yml" -f "$OVERLAY" --env-file "$CREDS" "$@"
}

# Read one key from credentials.env without sourcing (no eval of file content).
cred() { sed -n "s/^$1=//p" "$CREDS" | head -n1; }

# curl with basic auth supplied on stdin via -K, so the password is never in argv.
curl_auth() {
  local user="$1" pass="$2"; shift 2
  printf 'user = "%s:%s"\n' "$user" "$pass" | curl -sS -K - --cacert "$CERTS/root-ca.pem" "$@"
}

gen_password() {
  python3 - <<'PY'
import secrets, string
# Wazuh API policy: 8-64 chars with upper, lower, digit and a symbol.
# Avoid characters that break compose interpolation, YAML or sed: $ ' " | & \ ` #
alpha = string.ascii_letters + string.digits
sym = ".-+*?!"
while True:
    core = "".join(secrets.choice(alpha) for _ in range(22))
    pw = core + secrets.choice(sym) + secrets.choice(sym)
    pw = "".join(secrets.SystemRandom().sample(pw, len(pw)))
    if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw) and pw[0].isalnum()):
        print(pw)
        break
PY
}

key_mode() {
  # Indexer and dashboard run as uid 1000 inside their containers and read
  # the bind-mounted keys directly. If the host user is not uid 1000, make
  # the keys world-readable inside a 700 directory instead.
  if [[ "$(id -u)" == "1000" ]]; then echo 600; else echo 644; fi
}

make_cert() { # name CN SAN-list(ext string or empty) usage(server|client|both)
  local name="$1" cn="$2" san="$3" usage="$4" ext
  ext="$(mktemp)"
  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    case "$usage" in
      server) echo "extendedKeyUsage=serverAuth" ;;
      client) echo "extendedKeyUsage=clientAuth" ;;
      both)   echo "extendedKeyUsage=serverAuth,clientAuth" ;;
    esac
    [[ -n "$san" ]] && echo "subjectAltName=$san"
  } > "$ext"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CERTS/$name-key.pem" 2>/dev/null
  openssl req -new -key "$CERTS/$name-key.pem" -subj "/C=US/O=EmpowerU Wazuh Lab/OU=Lab/CN=$cn" -out "$CERTS/$name.csr"
  openssl x509 -req -in "$CERTS/$name.csr" -CA "$CERTS/root-ca.pem" -CAkey "$CERTS/root-ca-key.pem" \
    -CAcreateserial -days 825 -sha256 -extfile "$ext" -out "$CERTS/$name.pem" 2>/dev/null
  rm -f "$CERTS/$name.csr" "$ext"
}

do_generate() {
  command -v openssl >/dev/null || die "openssl is required"
  command -v python3 >/dev/null || die "python3 is required"
  mkdir -p "$CERTS"
  chmod 700 "$EU_LAB_GEN_DIR" "$CERTS"
  local km; km="$(key_mode)"

  if [[ -f "$CERTS/root-ca.pem" ]]; then
    echo "Certificates already exist in $CERTS (reusing; delete the directory to rotate)."
  else
    echo "Generating a lab-only root CA and certificates in $CERTS ..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$CERTS/root-ca-key.pem" 2>/dev/null
    openssl req -x509 -new -key "$CERTS/root-ca-key.pem" -sha256 -days 825 \
      -subj "/C=US/O=EmpowerU Wazuh Lab/OU=Lab/CN=EmpowerU Wazuh Lab Root CA" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$CERTS/root-ca.pem"
    make_cert indexer   wazuh-lab-indexer   "DNS:wazuh-lab-indexer,DNS:localhost,IP:127.0.0.1" both
    make_cert admin     admin               "" client
    make_cert manager   wazuh-lab-manager   "DNS:wazuh-lab-manager" client
    make_cert dashboard wazuh-lab-dashboard "DNS:wazuh-lab-dashboard,DNS:localhost,IP:127.0.0.1" server
    rm -f "$CERTS/root-ca.srl"
  fi
  chmod 644 "$CERTS"/*.pem
  chmod "$km" "$CERTS"/*-key.pem
  chmod 600 "$CERTS/root-ca-key.pem"

  if [[ -f "$CREDS" ]]; then
    echo "Credentials already exist in $CREDS (reusing)."
  else
    echo "Generating random passwords into $CREDS (mode 600; not printed) ..."
    {
      echo "# EmpowerU Wazuh lab dashboard credentials. Generated $(date '+%Y-%m-%d %H:%M %Z')."
      echo "# Lab only. Do not commit, paste, or share this file."
      echo "# Dashboard login: https://127.0.0.1:5601  user: admin  password: EU_LAB_INDEXER_ADMIN_PASSWORD"
      echo "EU_LAB_GEN_DIR=$EU_LAB_GEN_DIR"
      echo "EU_LAB_DASHBOARD_CONFIG_DIR=$CONFIG_DIR"
      echo "EU_LAB_INDEXER_BIND=$EU_LAB_INDEXER_BIND"
      echo "EU_LAB_DASHBOARD_BIND=$EU_LAB_DASHBOARD_BIND"
      echo "EU_LAB_INDEXER_ADMIN_PASSWORD=$(gen_password)"
      echo "EU_LAB_KIBANASERVER_PASSWORD=$(gen_password)"
      echo "EU_LAB_API_PASSWORD=$(gen_password)"
    } > "$CREDS"
  fi
  chmod 600 "$CREDS"

  if [[ -f "$EU_LAB_GEN_DIR/internal_users.yml" ]]; then
    echo "internal_users.yml already exists (reusing)."
  else
    echo "Hashing indexer passwords with the indexer image's hash tool ..."
    docker_init
    local admin_hash kib_hash
    # The password goes in on stdin (never argv, and it survives sudo).
    admin_hash="$(cred EU_LAB_INDEXER_ADMIN_PASSWORD | hash_pw || true)"
    kib_hash="$(cred EU_LAB_KIBANASERVER_PASSWORD | hash_pw || true)"
    [[ -n "$admin_hash" && -n "$kib_hash" ]] || die "could not hash passwords (is $INDEXER_IMAGE pullable?)"
    cat > "$EU_LAB_GEN_DIR/internal_users.yml" <<YAML
---
# Generated by lab/dashboard/dashboard.sh. bcrypt hashes only.
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$admin_hash"
  reserved: true
  backend_roles:
  - "admin"
  description: "EmpowerU lab admin (password in credentials.env)"

kibanaserver:
  hash: "$kib_hash"
  reserved: true
  description: "EmpowerU lab dashboard server user (password in credentials.env)"
YAML
  fi
  chmod "$km" "$EU_LAB_GEN_DIR/internal_users.yml"
  echo "Generated files are under $EU_LAB_GEN_DIR (directory 700)."
}

hash_pw() { # password on stdin -> bcrypt hash on stdout
  "${DC[@]}" run --rm -i -e JAVA_HOME=/usr/share/wazuh-indexer/jdk --entrypoint /bin/bash "$INDEXER_IMAGE" -c \
    'IFS= read -r EU_HASH_PW; export EU_HASH_PW; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env EU_HASH_PW' \
    2>/dev/null | grep -E '^[$]2' | tail -n1
}

wait_for() { # description, seconds, command...
  local what="$1" secs="$2"; shift 2
  local deadline=$(( SECONDS + secs ))
  printf 'Waiting for %s' "$what"
  until "$@" >/dev/null 2>&1; do
    (( SECONDS > deadline )) && { echo; die "timed out waiting for $what"; }
    printf '.'; sleep 5
  done
  echo " ok"
}
indexer_up() {
  curl_auth admin "$(cred EU_LAB_INDEXER_ADMIN_PASSWORD)" -f "https://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=5s"
}
dashboard_up() {
  local code
  code="$(curl_auth admin "$(cred EU_LAB_INDEXER_ADMIN_PASSWORD)" -o /dev/null -w '%{http_code}' "https://127.0.0.1:5601/api/status")"
  [[ "$code" == "200" ]]
}

do_up() {
  [[ -f "$EU_LAB_DIR/docker-compose.yml" ]] || die "no docker-compose.yml in $EU_LAB_DIR"
  do_generate
  docker_init
  echo "Starting manager + agent + indexer + dashboard (project $EU_LAB_PROJECT) ..."
  compose up -d
  wait_for "the indexer on https://127.0.0.1:9200" 300 indexer_up
  wait_for "the dashboard on https://127.0.0.1:5601" 420 dashboard_up
  echo "Dashboard is up: https://127.0.0.1:5601 (user admin; password is in $CREDS)"
}

do_import() {
  [[ -f "$CREDS" ]] || die "no $CREDS; run: CONFIRM=yes $0 up"
  [[ -f "$NDJSON" ]] || die "missing $NDJSON"
  echo "Importing $(basename "$NDJSON") (overwrite=true) ..."
  local out
  out="$(curl_auth admin "$(cred EU_LAB_INDEXER_ADMIN_PASSWORD)" -X POST \
    -H 'osd-xsrf: true' -F "file=@$NDJSON" \
    "https://127.0.0.1:5601/api/saved_objects/_import?overwrite=true")"
  python3 - "$out" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
print("success:", r.get("success"), " successCount:", r.get("successCount"))
for e in r.get("errors", []) or []:
    print("  error:", e.get("type"), e.get("id"), json.dumps(e.get("error")))
sys.exit(0 if r.get("success") else 1)
PY
}

do_verify() {
  [[ -f "$CREDS" ]] || die "no $CREDS; run: CONFIRM=yes $0 up"
  local pw; pw="$(cred EU_LAB_INDEXER_ADMIN_PASSWORD)"
  echo "== Indexer"
  curl_auth admin "$pw" "https://127.0.0.1:9200/_cluster/health" | python3 -c 'import json,sys; h=json.load(sys.stdin); print("cluster:", h["cluster_name"], "status:", h["status"])'
  curl_auth admin "$pw" "https://127.0.0.1:9200/_cat/indices/wazuh-alerts-*?h=index,docs.count&s=index"
  echo "== EmpowerU alerts indexed (all time), by rule.id"
  local ids_json; ids_json="$(printf '"%s",' "${EU_IDS[@]}")"; ids_json="[${ids_json%,}]"
  curl_auth admin "$pw" -H 'Content-Type: application/json' \
    "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=0" \
    -d "{\"query\":{\"terms\":{\"rule.id\":$ids_json}},\"aggs\":{\"ids\":{\"terms\":{\"field\":\"rule.id\",\"size\":20}}}}" |
    python3 -c 'import json,sys; r=json.load(sys.stdin); b=r["aggregations"]["ids"]["buckets"]; [print(f"  {x[\"key\"]}: {x[\"doc_count\"]}") for x in b] or print("  none yet")'
  echo "== Dashboard saved objects"
  curl_auth admin "$pw" "https://127.0.0.1:5601/api/saved_objects/dashboard/eu-ec-detect-starter-dashboard" |
    python3 -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d:
    print("  dashboard missing:", d.get("message")); sys.exit(1)
print("  dashboard:", d["attributes"]["title"])
for ref in d.get("references", []):
    print("   panel ref:", ref["type"], ref["id"])
'
  curl_auth admin "$pw" "https://127.0.0.1:5601/api/saved_objects/_find?type=visualization&search_fields=title&search=EU*&per_page=50" |
    python3 -c '
import json, sys
r = json.load(sys.stdin)
print("  visualizations found:", r.get("total"))
for o in r.get("saved_objects", []):
    print("   ", o["id"], "-", o["attributes"]["title"])
'
}

do_status() {
  docker_init
  "${DC[@]}" ps -a --filter "label=com.docker.compose.project=$EU_LAB_PROJECT" --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
  [[ -f "$CREDS" ]] && echo "credentials: $CREDS ($(stat -c %a "$CREDS" 2>/dev/null || stat -f %Lp "$CREDS"))"
  return 0
}

action="${1:-plan}"
case "$action" in
  plan)
    cat <<PLAN
Plan (nothing changes without CONFIRM=yes):
  lab compose dir : $EU_LAB_DIR (project $EU_LAB_PROJECT)
  overlay         : $OVERLAY
  generated files : $EU_LAB_GEN_DIR (700) — certs/, internal_users.yml, credentials.env (600)
  indexer         : $INDEXER_IMAGE on $EU_LAB_INDEXER_BIND:9200 (~2 GB RAM)
  dashboard       : wazuh/wazuh-dashboard:4.14.10 on $EU_LAB_DASHBOARD_BIND:5601
  manager         : recreated with Filebeat -> indexer and a random Wazuh API password
  import          : $NDJSON via the dashboard Saved Objects API
PLAN
    ;;
  generate) need_confirm "generate certs and passwords in $EU_LAB_GEN_DIR"; do_generate ;;
  up)       need_confirm "generate secrets (if missing) and start the indexer + dashboard overlay"; do_up ;;
  import)   need_confirm "import the starter dashboard into https://127.0.0.1:5601"; do_import ;;
  verify)   do_verify ;;
  status)   do_status ;;
  stop)     need_confirm "stop wazuh-lab-indexer and wazuh-lab-dashboard (manager and agent keep running)"
            docker_init; compose stop wazuh-dashboard wazuh-indexer ;;
  *) die "unknown action '$action' (plan|generate|up|import|verify|status|stop)" ;;
esac
