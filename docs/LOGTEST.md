# wazuh-logtest results — eu-wazuh-detections

**Manager:** `wazuh/wazuh-manager:4.14.10` (image digest `sha256:dcda4869e2f792e92f03bce93f85b4bdf103756ea61cfca8ba9f3eabeb05365b`). The image's `/var/ossec/VERSION.json` reports `"version": "4.14.10", "stage": "rc2", "commit": "6e7835b"`.

**When:** 2026-11-13, America/Los_Angeles 02:01 (manager `TZ` set so the 00:00–05:00 `<time>` window was active). The host running Docker was America/New_York.

**How:** Custom rules and the optional decoder were bind-mounted into `/var/ossec/etc/rules/` and `/var/ossec/etc/decoders/`. After `wazuh-analysisd` logged `Logtest started` and `Total rules enabled: 8466` with **no rule-load errors**, each sample in `tests/samples/` was piped to `/var/ossec/bin/wazuh-logtest` (frequency cases as a single session). Samples use RFC 5737 documentation IPs only.

`<time>` uses the manager's local clock, not the timestamp inside the log line.

## Per-rule table

| Rule ID | Sample | Expected leaf | Fired? | Leaf ID observed | Notes |
|---|---|---|---|---|---|
| 100002 | `100002-nc.log` | 100002 | yes | 100002 | Parent 530 confirmed. Also fired for `ncat`, `socat`, `python -m http.server`, and `busybox`. |
| 100010 | `session-100010-100011-pam.log` (8th PAM failure) | 100010 | yes | 100010 | Child of default 5551. Seven prior events were 5503. |
| 100011 | same session (PAM session opened after the burst) | 100011 | yes | 100011 | Parent is 5501 (PAM **success**). `same_source_ip` is omitted because PAM "session opened" logs have no `rhost`. |
| 100012 | `100012-pam-success.log` | 100012 | yes | 100012 | Parent 5501. A PAM **failure** (`5503-pam-failure.log`) now correctly leaves 5503 and does **not** fire 100012. |
| 100013 | `100013-ssh-root-success.log` | 100013 | yes | 100013 | Parent 5715, `<user>root</user>`. Wins over 100018 when both match (level 10 vs 8). |
| 100016 | `session-100016-100017-invalid-user.log` (8th `Invalid user`) | 100016 | yes | 100016 | Child of default 5712. |
| 100016 | `session-100016-100017-failed-password.log` (8th `Failed password`) | 100016 | yes | 100016 | Child of default 5763. "Failed password" is leaf 5760, not 5716. |
| 100017 | both SSH sessions above (success after the burst) | 100017 | yes | 100017 | Parent 5715, `if_matched_sid` 100016, `same_source_ip`. |
| 100018 | `100018-ssh-user-success.log` | 100018 | yes | 100018 | Non-root SSH success during the `<time>` window. |
| 100020 | `100020-fim-usr-bin.json` | 100020 | **no** via logtest; **yes** on a real FIM event | 100020 (live lab) | logtest still cannot invoke the FIM plugin decoder. On a live 4.14.10 manager + agent (2026-11-13, America/New_York), a realtime mtime change on `/usr/bin/ls` produced leaf **100020** (parent 550, `decoded_as` `syscheck_integrity_changed`). See [SETUP-WAZUH-LAB.md](SETUP-WAZUH-LAB.md). |
| 100021 | `100021-fim-sshd-config.json` | 100021 | **no** via logtest; **yes** on a real FIM event | 100021 (live lab) | Same logtest limitation. A realtime content change on `/etc/ssh/sshd_config` produced leaf **100021**. New files fire default 554, not these rules. |

## Fixes confirmed by this run

On the rules as first published, `wazuh-logtest` against 4.14.10 showed:

- **5501 is PAM success** ("Login session opened") and **5503 is PAM failure**. The draft had them swapped. 100012 fired on failed PAM logins during 00:00–05:00, and 100010 did not count real failures.
- Sibling copies of default frequency rules **never became the leaf**: 8 invalid-user events produced default 5712 (not 100016); 8 failed-password events produced default 5763; 8 PAM failures would produce default 5551. The EmpowerU IDs are now children of those defaults so the labeled alert is the one generated.
- SSH "Failed password" is default **5760**, not 5716. Default 5720 (`if_matched_sid` 5716) did not fire. 100016 therefore parents 5712 and 5763.

## FIM live verification (100020 and 100021)

`wazuh-logtest` still cannot fire these IDs: it does not invoke the FIM plugin decoder, and the JSON samples decode as generic JSON rather than rule 550. They **were** validated on a live manager: `wazuh-lab-manager` + `wazuh-lab-agent` (`wazuh/wazuh-manager:4.14.10` and `wazuh/wazuh-agent:4.14.10`, VERSION.json `4.14.10` / `rc2` / `6e7835b`) on 2026-11-13 at 1:55 PM America/New_York. `touch /usr/bin/ls` produced leaf 100020 (mode realtime, changed attribute `mtime`). Appending a comment to `/etc/ssh/sshd_config` produced leaf 100021 (changed attributes size, mtime, md5, sha1, sha256). `full_log` contains the path (`File '/usr/bin/ls' modified`), so the existing `<match>` options are enough; no rule change was required. A newly created file is default 554 and does not match these rules. Step-by-step instructions: [SETUP-WAZUH-LAB.md](SETUP-WAZUH-LAB.md).

## Not verified

- **Optional collector JSON decoder.** The built-in `json` decoder wins for collector summaries that start with `{"timestamp":`. Fields are extracted; `eu-ec-collect-json` is not the selected decoder. The detection rules do not depend on it.
- **Starter dashboard.** Still untested against OpenSearch Dashboards. This lab does not run a dashboard container.
- **Wazuh 5.x** and versions other than 4.14.10. Parent SIDs should be re-checked on the manager you will run.

The Wazuh manager ran only in a disposable container on this computer. Wazuh packages were not installed on the host. The container was not left as a service.
