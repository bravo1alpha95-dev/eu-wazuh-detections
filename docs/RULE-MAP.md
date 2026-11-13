# Rule map — eu-wazuh-detections

Every custom rule lives in `rules/eu_ec_detect_rules.xml`. IDs are in the Wazuh custom range (100000+).

**Verified with `wazuh-logtest` against `wazuh/wazuh-manager:4.14.10` on 2026-11-13.** See [LOGTEST.md](LOGTEST.md) for the per-rule table, sample files, and what is still unverified. Parent SIDs below are those confirmed on 4.14.10; they can still change between versions, so confirm them on your manager before deploying. Tune frequencies, hours, and match lists to your baseline.

The `<time>` option uses the **manager's local clock**, not the timestamp in the log.

MITRE ATT&CK identifiers are included only where the mapping is clearly accurate. Absence of a MITRE ID is intentional.

| Rule ID | What it detects | Parent / correlation (4.14.10) | MITRE ATT&CK | Source in the toolkit | logtest on 4.14.10 |
|---|---|---|---|---|---|
| 100002 | Start of a process commonly used as an unexpected network listener (`nc`, `ncat`, `socat`, `python -m http`, `busybox`) | `if_sid` 530 (process-monitoring command output) | T1571 Non-Standard Port | `anomaly-checks.sh` unexpected-listener check | fired (all five match strings) |
| 100010 | Multiple failed PAM/syslog logins from the same source IP | `if_sid` 5551 (default: 8x 5503 in 180s, `same_source_ip`). 5503 is PAM **failure**; 5501 is success | T1110 Brute Force | collector / anomaly auth excerpts | fired (8th failure in a session) |
| 100016 | Multiple failed SSH logins from the same source IP | `if_sid` 5712 (invalid-user burst) and 5763 (failed-password burst). "Failed password" is leaf 5760, not 5716 | T1110 Brute Force | SSH-specific companion | fired on both burst types |
| 100011 | Successful PAM/syslog login after a 100010 burst | `if_sid` 5501 (PAM session opened), `if_matched_sid` 100010. No `same_source_ip` (PAM success logs often lack `rhost`) | T1110 Brute Force, T1078 Valid Accounts | correlation after a PAM burst | fired |
| 100017 | Successful SSH login from a source that just tripped 100016 | `if_sid` 5715, `if_matched_sid` 100016, `same_source_ip` | T1110 Brute Force, T1078 Valid Accounts | SSH-specific companion | fired |
| 100012 | Successful PAM/syslog login between 00:00 and 05:00 (manager local time) | `if_sid` 5501, `time` | none — baseline-deviation, not a single ATT&CK technique | `anomaly-checks.sh` unusual-hours section | fired; PAM failures no longer trigger it |
| 100018 | Successful SSH login between 00:00 and 05:00 (manager local time) | `if_sid` 5715, `time` | none — same reason as 100012 | same | fired (non-root). Root success prefers 100013 |
| 100013 | Successful SSH login as `root` | `if_sid` 5715, `user` root | T1078 Valid Accounts | collector SSH-policy excerpts (`PermitRootLogin`) | fired |
| 100020 | File-integrity change under `/usr/bin`, `/usr/sbin`, `/bin`, or `/sbin` | `if_sid` 550 (FIM checksum-changed, plugin decoder) | none — a path change is not, by itself, one ATT&CK technique | original policy FIM example | **loaded, not fired via logtest** (FIM plugin decoder is not invoked) |
| 100021 | File-integrity change on `sshd_config` or sudoers paths | `if_sid` 550 | none — same reason as 100020 | collector reviews of SSH and sudo policy files | **loaded, not fired via logtest** |

Default Wazuh already ships SSH and PAM correlation rules (5551, 5712, 5763, 40112, and others). 100010 and 100016 are **children** of those defaults so the EmpowerU-labeled alert is the leaf. If you see duplicate alerts you do not want, lower a level here or disable the overlapping default after review.

## Decoders

`decoders/eu_ec_detect_decoders.xml` is optional. On 4.14.10 the built-in `json` decoder wins for collector JSON summaries; fields are still extracted. The table above does not depend on this decoder.
