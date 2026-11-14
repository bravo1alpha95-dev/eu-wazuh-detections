# Attack-simulation lab — watch every EmpowerU rule fire

`lab/simulate/` is a small set of **defensive, local-only** scripts that make the Docker lab's agent produce the events each EmpowerU rule is written for, then read the manager's `alerts.json` and report which rule IDs fired. Pair it with the optional dashboard ([SETUP-WAZUH-LAB.md, step 6](SETUP-WAZUH-LAB.md#6-optional-add-the-indexer-and-dashboard)) to see the alerts on the starter dashboard.

## Safety model

- **Dry-run by default.** Every script prints what it would do. Nothing changes unless you set `CONFIRM=yes`.
- **One target only.** The scripts act on the lab agent container (`wazuh-lab-agent`) through `docker exec`. Before any change they check that both `wazuh-lab-agent` and `wazuh-lab-manager` are running **and** carry the Docker Compose label `com.docker.compose.project=wazuh-lab`. There is no option to aim them at a host, IP address, or URL.
- **No network traffic and no real logins.** Authentication, sudo, new-user and process events are **synthetic log lines** appended to `/var/log/eu-sim/auth.log` *inside the agent container*. The lab's shared agent config (`lab/manager/agent.conf`) tells the agent to read that file. Source IPs are RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); the scripts refuse anything else.
- **File-integrity events are real but harmless**: `touch /usr/bin/ls` (mtime only) and comment lines tagged `EU-SIM` in `/etc/ssh/sshd_config` and `/etc/sudoers.d/eu-sim` inside the agent container. The sudoers file only ever contains comments, so it grants nothing. `90-cleanup.sh` removes the tagged lines and files.

Synthetic lines go through the same agent → manager → decoder → rule pipeline as real logs, including the frequency and correlation rules. What they do **not** prove is that your real `sshd`/PAM writes exactly these formats; that part is covered by `wazuh-logtest` with the samples in `tests/samples/` and by your own logs.

## Run it

Start the lab first ([SETUP-WAZUH-LAB.md](SETUP-WAZUH-LAB.md), steps 1–4; run `lab/fim-test.sh` once so `sshd_config` is in the FIM baseline). Then, from `lab/`:

```bash
./simulate/run-all.sh                  # dry run: prints every step, changes nothing
CONFIRM=yes ./simulate/run-all.sh      # act on wazuh-lab-agent and check alerts.json
```

If your user cannot reach Docker directly, the scripts fall back to `sudo -n docker` (no password prompt). Run `sudo -v` first so sudo has cached your password, or add your user to the `docker` group.

If the agent was enrolled before you pulled this version, give it about a minute to download the updated shared config (the agent restarts itself), or `docker restart wazuh-lab-agent`. `00-prepare.sh` warns if the agent does not yet monitor `/var/log/eu-sim/auth.log`.

Options: `EU_SIM_ONLY="fim pam-burst"` runs a subset; `EU_SIM_WAIT=120` waits longer for alerts; `EU_SIM_REPORT_DIR` changes where reports go (default `lab/simulate/results/`, git-ignored, directory 700 and files 600). Reports keep only selected alert fields (time, rule, location, documentation source IP, FIM path) — no container IPs.

## Scenarios and expected rules

Run order matters: 100011 correlates **any** PAM success within 180 s after 100010 (it has no `same_source_ip`, because PAM "session opened" lines carry no `rhost`), so the PAM burst runs after the scenarios that log other PAM successes.

| Script | What it does | Expected rule IDs |
|---|---|---|
| `10-root-ssh.sh` | Synthetic `Accepted publickey for root` | **100013** (parent 5715) |
| `20-offhours.sh` | Synthetic non-root PAM session opened + SSH accepted | **100012**, **100018** only when the *manager's* local clock is 00:00–05:00; otherwise defaults 5501 and 5715 (correct behavior) |
| `30-listener.sh` | Synthetic Wazuh process-monitor output naming `nc -l` (no listener is opened) | **100002** (parent 530) |
| `40-user-sudo.sh` | Synthetic `useradd` and `sudo` lines; real comment-only edit of `/etc/sudoers.d/eu-sim` | default 5902 (new user), 5402 or 5403 (sudo; 5403 is "first time this user ran sudo"), 554 on the first run (file added), **100021** (policy file modified) |
| `50-fim.sh` | Real `touch /usr/bin/ls`; real comment appended to `/etc/ssh/sshd_config` | **100020**, **100021** (parent 550) |
| `60-pam-burst.sh` | 8 synthetic PAM failures from one IP, then a PAM session opened | 5503 → 5551 → **100010**, then **100011** |
| `70-ssh-burst.sh` | 8 synthetic `Invalid user` from one IP, then `Accepted password` from that IP | 5710 → 5712 → **100016**, then **100017** |
| `90-cleanup.sh` | Removes `EU-SIM` lines, `/etc/sudoers.d/eu-sim`, and empties the synthetic log | FIM events from the cleanup itself |

EmpowerU has no custom rule for new users or sudo; the default Wazuh rules cover those, and the scenario shows them next to the EmpowerU sudo-policy FIM alert.

## Results on the live lab (2026-11-14, America/New_York)

Manager and agent `wazuh/wazuh-manager:4.14.10` / `wazuh/wazuh-agent:4.14.10` (VERSION.json `4.14.10`, `rc2`), with the indexer and dashboard overlay running. Two full runs, started at 11:32 AM and 11:43 AM EST, both passed every scenario with identical results (table below). The manager's local hour was 11, so the off-hours window was closed.

| Scenario | Expected | Fired | Result |
|---|---|---|---|
| root-ssh | 100013 | 100013 | PASS |
| offhours (window closed) | 5501, 5715 | 5501, 5715 | PASS |
| listener | 100002 | 100002 | PASS |
| user-sudo | 5902, 5402 or 5403, 100021 | 5902, 5402, 100021 | PASS |
| fim | 100020, 100021 | 100020, 100021 | PASS |
| pam-burst | 5503, 100010, 100011 | 5503, 100010, 100011 | PASS |
| ssh-burst | 5710, 100016, 100017 | 5710, 100016, 100017 | PASS |

EmpowerU leaf alerts seen in that run: 100002, 100010, 100011, 100013, 100016, 100017, 100020, 100021 (twice: `sshd_config` and `sudoers.d/eu-sim`). The alerts also reached the indexer and appear on the starter dashboard. A dry run (`./simulate/run-all.sh` without `CONFIRM`) printed every step and changed nothing.

Honest notes from the runs:

- **100012 and 100018 were not fired live**, because the runs happened in the daytime and Wazuh `<time>` uses the manager's clock. They fire through `wazuh-logtest` with the manager clock inside the window on every version in the CI matrix ([LOGTEST.md](LOGTEST.md)). To see them live, run the simulation between 00:00 and 05:00 manager time.
- **The first full run** (11:26 AM EST, minutes after the agent picked up the new shared config) produced eight 5503 alerts but **no 5551/100010/100011**. Running only `pam-burst` again right after, and the next full run, both passed. The cause was not pinned down; if you see it, re-run `EU_SIM_ONLY=pam-burst CONFIRM=yes ./simulate/run-all.sh`.
- The first run also showed **5403** ("first time user executed sudo") instead of 5402. Both are default sudo rules; the runner accepts either.

## Clean up

```bash
CONFIRM=yes ./simulate/90-cleanup.sh
```

Or remove the whole lab: `docker compose down -v` (see [SETUP-WAZUH-LAB.md](SETUP-WAZUH-LAB.md#5-tear-down)).
