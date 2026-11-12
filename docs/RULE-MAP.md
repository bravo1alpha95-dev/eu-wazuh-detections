# Rule map — eu-wazuh-detections

Every custom rule lives in `rules/eu_ec_detect_rules.xml`. IDs are in the Wazuh custom range (100000+).

**These rules have not been tested with `wazuh-logtest` against a live Wazuh manager.** Parent SIDs (`530`, `550`, `5501`, `5503`, `5710`, `5715`) come from default Wazuh rule sets and can change between versions. Confirm them on your manager before deploying. Tune frequencies, hours, and match lists to your baseline.

MITRE ATT&CK identifiers are included only where the mapping is clearly accurate. Absence of a MITRE ID is intentional.

| Rule ID | What it detects | Parent / correlation | MITRE ATT&CK | Source in the toolkit |
|---|---|---|---|---|
| 100002 | Start of a process commonly used as an unexpected network listener (`nc`, `ncat`, `socat`, `python -m http`, `busybox`) | `if_sid` 530 (default process-start) | T1571 Non-Standard Port | `anomaly-checks.sh` unexpected-listener check; original policy example |
| 100010 | Multiple failed PAM/syslog logins from the same source IP (8 events in 120 seconds; tune as needed) | `if_matched_sid` 5501, `same_source_ip` | T1110 Brute Force | collector / anomaly auth excerpts; original policy example (frequency added so "multiple" is actually enforced) |
| 100016 | Multiple failed SSH logins from the same source IP (same threshold) | `if_matched_sid` 5710, `same_source_ip` | T1110 Brute Force | same, SSH-specific companion |
| 100011 | Successful PAM/syslog login from a source that just tripped 100010 | `if_sid` 5503, `if_matched_sid` 100010 | T1110 Brute Force, T1078 Valid Accounts | original policy example, correlation direction corrected |
| 100017 | Successful SSH login from a source that just tripped 100016 | `if_sid` 5715, `if_matched_sid` 100016 | T1110 Brute Force, T1078 Valid Accounts | SSH-specific companion |
| 100012 | Successful PAM/syslog login between 00:00 and 05:00 | `if_sid` 5503, `time` | none — this is a baseline-deviation check, not a single ATT&CK technique | `anomaly-checks.sh` unusual-hours section |
| 100018 | Successful SSH login between 00:00 and 05:00 | `if_sid` 5715, `time` | none — same reason as 100012 | same |
| 100013 | Successful SSH login as `root` | `if_sid` 5715, `user` root | T1078 Valid Accounts | collector SSH-policy excerpts (`PermitRootLogin`) |
| 100020 | File-integrity change under `/usr/bin`, `/usr/sbin`, `/bin`, or `/sbin` | `if_sid` 550 (default FIM checksum-changed) | none — a path change is not, by itself, one ATT&CK technique | original policy FIM example; MITRE IDs from that example were not carried over because they were not clearly accurate |
| 100021 | File-integrity change on `sshd_config` or sudoers paths | `if_sid` 550 | none — same reason as 100020 | collector reviews of SSH and sudo policy files |

Default Wazuh already ships some SSH and PAM correlation rules. If you see duplicate alerts, lower a level here or disable the overlapping default after review.

## Decoders

`decoders/eu_ec_detect_decoders.xml` is optional. It only classifies collector JSON summaries if you ship those files to the manager. The table above does not depend on it.
