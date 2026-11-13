# Set up a Wazuh lab and test the EmpowerU FIM rules

This guide walks you through a small **Docker lab**: one Wazuh manager and one Wazuh agent, both version 4.14.10. You will load the EmpowerU custom rules and confirm that file-integrity rules **100020** and **100021** fire on a real change, not just a syntax check.

You do **not** need a production Wazuh server for this. The lab is disposable. It is **not** a production install: it uses an open enrollment port with no password, and it does not include the Wazuh indexer or dashboard.

These steps were run successfully on 2026-11-13 (America/New_York) against `wazuh/wazuh-manager:4.14.10` and `wazuh/wazuh-agent:4.14.10`. Both custom rules fired. The results are summarized at the end of this page.

If a command below starts with `docker` and your shell says "permission denied" on `/var/run/docker.sock`, put `sudo` in front (`sudo docker compose`, `sudo docker exec`, and so on). On Docker Desktop for Mac, `sudo` is usually not needed.

---

## What you need

- A Linux or Mac computer you own, with:
  - [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
  - Docker Compose v2 (included with current Docker Desktop and current Docker Engine; check with `docker compose version`)
  - Git
- About **2 CPUs and 2–4 GB of RAM** free for this slim lab (manager + agent only). That is much less than a full Wazuh all-in-one server, which also runs the indexer and dashboard.
- Free ports **1514**, **1515**, and **55000** on the host. If something else already uses them, change the left-hand side of the port mappings in `lab/docker-compose.yml` (for example `"1514:1514"` becomes `"11514:1514"`) and use the new host port in any troubleshooting steps.

Do not publish those ports to the public internet. This lab's enrollment service accepts new agents without a password.

---

## 1. Get the files

```bash
git clone https://github.com/bravo1alpha95-dev/eu-wazuh-detections.git
cd eu-wazuh-detections/lab
```

The compose file in this directory starts the two containers and bind-mounts:

- `rules/eu_ec_detect_rules.xml` into `/var/ossec/etc/rules/` on the manager
- `decoders/eu_ec_detect_decoders.xml` into `/var/ossec/etc/decoders/` on the manager
- `lab/manager/agent.conf` into the manager's shared agent configuration, which is pushed to the agent (60-second FIM scans, realtime on `/etc` and `/usr/bin`)

---

## 2. Start the lab

From the `lab/` directory:

```bash
docker compose up -d
```

The first run pulls the official images (a few gigabytes for the manager) and then starts two containers:

| Container name        | Image                         | Role |
|-----------------------|-------------------------------|------|
| `wazuh-lab-manager`   | `wazuh/wazuh-manager:4.14.10` | Analyzes events and writes alerts |
| `wazuh-lab-agent`     | `wazuh/wazuh-agent:4.14.10`   | Enrolls to the manager and monitors files |

Wait until the manager is up and the agent is **Active**. This usually takes under a minute.

```bash
# Manager processes (authd, analysisd, remoted should be "is running")
docker exec wazuh-lab-manager /var/ossec/bin/wazuh-control status

# Agent should appear as Active (not "Never connected" or "Pending")
docker exec wazuh-lab-manager /var/ossec/bin/agent_control -l
```

You want a line like:

```text
ID: 001, Name: wazuh-lab-agent, IP: any, Active
```

If the agent stays on "Never connected", see [Troubleshooting](#troubleshooting).

A note you can ignore: the agent image's init script may log `[cont-init.d] 0-wazuh-init: exited 1` when no enrollment password is set. The agent still starts. That exit code is from an empty-password check, not a failed configuration.

---

## 3. Confirm the rules loaded

Custom files under `/var/ossec/etc/rules/` and `/var/ossec/etc/decoders/` are picked up automatically. Check the manager log for a clean load (no rule-parse errors) and a total close to 8466 on 4.14.10:

```bash
docker exec wazuh-lab-manager grep -E 'Total rules|ERROR|error:|eu_ec' /var/ossec/logs/ossec.log | tail
docker exec wazuh-lab-manager ls -la /var/ossec/etc/rules/ /var/ossec/etc/decoders/
```

You should see `eu_ec_detect_rules.xml` and `eu_ec_detect_decoders.xml` in those directories.

The shared FIM settings are in `lab/manager/agent.conf`. After the agent is Active, the agent log should show realtime monitoring and a 60-second frequency:

```bash
docker exec wazuh-lab-agent grep -E 'realtime|frequency: 60|Directory set for real time' /var/ossec/logs/ossec.log | tail
```

---

## 4. Run the file-integrity test

**Why this step is a little careful:** Wazuh uses different default rule IDs for different FIM events.

| Default ID | Meaning | Do our rules 100020 / 100021 match? |
|------------|---------|--------------------------------------|
| **550** | Integrity checksum changed — a file **already in the baseline** was modified | Yes (`<if_sid>550</if_sid>`) |
| **554** | File added — a **new** file appeared | No |
| **553** | File deleted | No |

If `/etc/ssh/sshd_config` does not exist and you create it, the first event is 554, and 100021 will **not** fire. Create the file, wait for a scan to put it in the baseline, **then** modify it. `/usr/bin/ls` already exists in the agent image, so a modification there is a 550 event from the start.

You can run the packaged script, which handles a missing `sshd_config` and then makes the two modifications:

```bash
# still in eu-wazuh-detections/lab
./fim-test.sh
```

Or do the same thing by hand.

**If `sshd_config` is missing**, create it and let a scan finish first:

```bash
docker exec wazuh-lab-agent bash -c 'mkdir -p /etc/ssh; test -f /etc/ssh/sshd_config || echo "# EmpowerU FIM lab baseline" > /etc/ssh/sshd_config'
docker exec wazuh-lab-manager /var/ossec/bin/agent_control -r -u 001
# wait until the agent log shows "File integrity monitoring scan ended"
sleep 20
```

**Then modify two existing files.** The first command only updates the timestamp of `/usr/bin/ls`; it does not change the program's contents. The second appends a comment, which is enough for a content change and does not alter SSH settings in a meaningful way.

```bash
docker exec wazuh-lab-agent touch /usr/bin/ls
docker exec wazuh-lab-agent bash -c 'echo "# lab FIM test, safe comment only" >> /etc/ssh/sshd_config'
```

Realtime monitoring should send the events immediately. You can also request a scheduled scan as a backup:

```bash
docker exec wazuh-lab-manager /var/ossec/bin/agent_control -r -u 001
```

**Read the alerts** on the manager (JSON, one object per line):

```bash
docker exec wazuh-lab-manager python3 -c '
import json
with open("/var/ossec/logs/alerts/alerts.json") as f:
    for line in f:
        if not line.strip():
            continue
        a = json.loads(line)
        rid = str(a.get("rule", {}).get("id"))
        path = (a.get("syscheck") or {}).get("path", "")
        if rid in {"550", "554", "100020", "100021"} or "sshd" in path or path.endswith("/ls"):
            print(rid, a["rule"]["description"], path, (a.get("syscheck") or {}).get("event"))
'
```

### What success looks like

You should see **leaf** alerts `100020` (for `/usr/bin/ls`) and `100021` (for `/etc/ssh/sshd_config`), both at level 12. You will **not** usually see rule 550 as the leaf ID for those same events: 100020 and 100021 are children of 550, so they replace 550 as the alert that is written.

On the 2026-11-13 lab run (America/New_York), realtime FIM produced:

**100020** — fired, yes — at 1:55:15 PM America/New_York:

```text
rule.id:          100020
rule.level:       12
rule.description: eu-ec-detect: critical binary path modified (file integrity)
decoder:          syscheck_integrity_changed
syscheck.path:    /usr/bin/ls
syscheck.event:   modified
syscheck.mode:    realtime
changed:          mtime

full_log:
File '/usr/bin/ls' modified
Mode: realtime
Changed attributes: mtime
```

**100021** — fired, yes — at 1:55:15 PM America/New_York:

```text
rule.id:          100021
rule.level:       12
rule.description: eu-ec-detect: SSH or sudo policy file modified (file integrity)
decoder:          syscheck_integrity_changed
syscheck.path:    /etc/ssh/sshd_config
syscheck.event:   modified
syscheck.mode:    realtime
changed:          size, mtime, md5, sha1, sha256

full_log:
File '/etc/ssh/sshd_config' modified
Mode: realtime
Changed attributes: size,mtime,md5,sha1,sha256
Size changed from '28' to '89'
```

`<match>` in those rules looks at `full_log`. On 4.14.10 the path is in that text (`File '/usr/bin/ls' modified`), so the current rules match a real FIM event. `wazuh-logtest` still cannot exercise these two IDs, because it does not invoke the FIM plugin decoder; that is a logtest limitation, not a rule bug.

If you only see **554**, the file was new, not modified. If you only see **550**, the custom rules did not load (go back to step 3). If you see nothing, the agent is not monitoring that path, or the event has not arrived yet — check `agent_control -l` and the agent syscheck log.

---

## 5. Tear down

Leave the lab running if you still want to inspect alerts. When you are done:

```bash
# From eu-wazuh-detections/lab
docker compose down        # stop and remove containers; keep volumes
docker compose down -v     # also delete lab volumes (alerts and keys)
```

`down -v` is a complete wipe of this lab's data. It does not remove the Docker images; you can delete those later with `docker image rm wazuh/wazuh-manager:4.14.10 wazuh/wazuh-agent:4.14.10` if you want the disk back.

---

## Troubleshooting

**The agent logs `Could not resolve hostname: wazuh-lab-manager` or times out connecting.**
The compose file already sets `extra_hosts` so `wazuh-lab-manager` points at the Docker host gateway, and it publishes ports 1514 and 1515. That path works when Docker's built-in DNS or container-to-container traffic is blocked (for example, Docker Engine started with `"iptables": false`). Confirm the ports are published (`docker ps`) and not taken by another process. If you changed the host port mappings, either change them back or point the agent's `WAZUH_MANAGER_PORT` / `WAZUH_REGISTRATION_PORT` at the new host ports.

**The agent image ignores `WAZUH_MANAGER`.**
On `wazuh/wazuh-agent:4.14.10`, the init script substitutes **`WAZUH_MANAGER_SERVER`** into `<address>`. The compose file sets both. If you start a container by hand, set `WAZUH_MANAGER_SERVER`.

**Rules are mounted but analysisd started before the files were there.**
Restart the manager after the bind mounts are in place: `docker restart wazuh-lab-manager`. Then wait for the agent to become Active again (it will reconnect).

**I created `sshd_config` and only got rule 554.**
That is expected for a new file. Append a comment after the first scan has finished, and 100021 should fire on the 550 (modified) event.

---

## Optional: a real single-node Wazuh server (not Docker)

If you later want a full Wazuh server (manager + indexer + dashboard) on a Linux host you own, use the official [Quickstart](https://documentation.wazuh.com/current/quickstart.html). The command and hardware figures below were checked against that page on 2026-11-13. Re-read the page before you run anything; Wazuh updates the package path when the version changes.

**Hardware** (all three central components on one host, about 90 days of alerts):

| Agents | CPU    | RAM   | Storage |
|--------|--------|-------|---------|
| 1–25   | 4 vCPU | 8 GiB | 50 GB   |
| 26–50  | 8 vCPU | 8 GiB | 100 GB  |
| 51–100 | 8 vCPU | 8 GiB | 200 GB  |

**Operating system:** a 64-bit Intel, AMD, or ARM Linux host. Wazuh recommends Amazon Linux 2 or 2023, CentOS Stream 10, Red Hat Enterprise Linux 7–10, or Ubuntu 16.04, 18.04, 20.04, 22.04, or 24.04.

**Install** (current official command, using the 4.14 assistant — not a generic `4.x` URL):

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

The assistant prints the dashboard URL and an `admin` password when it finishes. Open `https://<that-host>` in a browser. The first visit shows a certificate warning for the lab-style self-signed certificate; that is expected. Passwords are also stored in `wazuh-install-files.tar` in the directory where you ran the script:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

**Load the EmpowerU rules** on that manager the same way the Docker lab does, then restart the manager:

```bash
git clone https://github.com/bravo1alpha95-dev/eu-wazuh-detections.git
sudo cp eu-wazuh-detections/rules/eu_ec_detect_rules.xml /var/ossec/etc/rules/
sudo cp eu-wazuh-detections/decoders/eu_ec_detect_decoders.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/rules/eu_ec_detect_rules.xml /var/ossec/etc/decoders/eu_ec_detect_decoders.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

For the FIM test, run the modify-and-watch steps on a **Wazuh agent** enrolled to that manager, with syscheck covering `/etc` and `/usr/bin`. The alert file on a package-installed manager is the same path: `/var/ossec/logs/alerts/alerts.json`.

To uninstall a Quickstart install: `sudo bash ./wazuh-install.sh -u` (see the same Quickstart page).

This Docker lab does **not** start the dashboard, so the starter `dashboards/eu-ec-detect-starter.ndjson` export is still untested. Importing it requires a running Wazuh dashboard (OpenSearch Dashboards), which is part of the full single-node install above.

