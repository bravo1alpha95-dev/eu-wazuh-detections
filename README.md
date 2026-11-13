# eu-wazuh-detections

Wazuh custom rules, optional decoders, and a **starter** dashboard derived from EmpowerU LLC's community access-monitoring toolkit ([eu-ec-detect-community](https://github.com/bravo1alpha95-dev/eu-ec-detect-community)).

**Defensive only. Owned systems only.** This pack does not include offensive detections, exploit content, or targeting of third-party systems.

## Tested on Wazuh 4.14.10

Custom rules were loaded into the official `wazuh/wazuh-manager:4.14.10` container and exercised with `wazuh-logtest` and the synthetic samples in [tests/samples/](tests/samples/). Nine of eleven rule IDs fired as the leaf alert with the expected parents through logtest. File-integrity rules 100020 and 100021 **loaded** in logtest (the FIM plugin decoder is not invoked there) and **fired** on a live manager + agent on 2026-11-13: 100020 on a realtime mtime change to `/usr/bin/ls`, 100021 on a realtime content change to `/etc/ssh/sshd_config`. How to repeat that lab: [docs/SETUP-WAZUH-LAB.md](docs/SETUP-WAZUH-LAB.md). The starter dashboard is still untested. Details, parent-SID corrections (PAM 5501/5503 were swapped in the first draft), and leftover gaps are in [docs/LOGTEST.md](docs/LOGTEST.md).

Parent rule IDs can still vary by version. Re-run `wazuh-logtest` on **your** manager, and tune thresholds, hours, and match lists to your baseline, before you rely on the alerts. The `<time>` window uses the manager's local clock.

The dashboard export is a starter. It is untested and may need adjustments for your Wazuh and OpenSearch Dashboards versions. See [dashboards/README.md](dashboards/README.md).

## Contents

| Path | What it is |
|---|---|
| [rules/eu_ec_detect_rules.xml](rules/eu_ec_detect_rules.xml) | Custom rules, IDs in the 100000+ range |
| [docs/RULE-MAP.md](docs/RULE-MAP.md) | Each rule, what it detects, and MITRE ATT&CK IDs (only where clearly accurate) |
| [decoders/eu_ec_detect_decoders.xml](decoders/eu_ec_detect_decoders.xml) | Optional classifier for collector JSON; the rules do not depend on it |
| [dashboards/eu-ec-detect-starter.ndjson](dashboards/eu-ec-detect-starter.ndjson) | Starter saved-object export (untested) |
| [examples/ossec-agent-snippets.conf](examples/ossec-agent-snippets.conf) | Optional agent FIM and manager-address snippets |
| [docs/SETUP-WAZUH-LAB.md](docs/SETUP-WAZUH-LAB.md) | Step-by-step Docker lab (manager + agent) and official single-node install notes |
| [lab/](lab/) | Compose file and `fim-test.sh` for that Docker lab |

Related: [eu-monitor-installer](https://github.com/bravo1alpha95-dev/eu-monitor-installer) can copy these rules onto a manager you operate (dry-run by default). Documentation site: [eu-security-site](https://github.com/bravo1alpha95-dev/eu-security-site).

## Rule summary

| ID | Detects | MITRE |
|---|---|---|
| 100002 | Unexpected process often used as a network listener (`nc`, `ncat`, `socat`, `python -m http`, `busybox`) | T1571 |
| 100010 | Multiple failed PAM/syslog logins from one source | T1110 |
| 100016 | Multiple failed SSH logins from one source | T1110 |
| 100011 | Successful PAM/syslog login after that burst | T1110, T1078 |
| 100017 | Successful SSH login after that burst | T1110, T1078 |
| 100012 | Successful PAM/syslog login between 00:00 and 05:00 | none (baseline deviation) |
| 100018 | Successful SSH login between 00:00 and 05:00 | none (baseline deviation) |
| 100013 | Successful SSH login as root | T1078 |
| 100020 | FIM change under `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` | none |
| 100021 | FIM change on `sshd_config` or sudoers paths | none |

See [docs/RULE-MAP.md](docs/RULE-MAP.md) for parent SIDs, rationale, and what was intentionally not mapped to ATT&CK.

## Install (manager you operate)

1. Back up the manager configuration and take a snapshot.
2. Copy `rules/eu_ec_detect_rules.xml` to the manager custom-rules directory (commonly `/var/ossec/etc/rules/` on a Wazuh manager). Set ownership and mode to match the other rule files.
3. Optionally copy `decoders/eu_ec_detect_decoders.xml` to the custom-decoders directory if you will ingest collector JSON.
4. On the manager, run `wazuh-logtest` against the samples in `tests/samples/` (and your own logs) for your Wazuh version. Confirm parent SIDs still mean what [docs/RULE-MAP.md](docs/RULE-MAP.md) assumes. On 4.14.10: 5501 is PAM **success**, 5503 is PAM **failure**; SSH "Failed password" is 5760.
5. Restart or reload the manager only after that review, and only on a system you own, under your own change control.

The [eu-monitor-installer](https://github.com/bravo1alpha95-dev/eu-monitor-installer) Ansible role can perform the copy in check mode (`--check`) first.

Do not paste unreviewed production alerts into public issues.

## Checks

```bash
python3 tests/test_xml_wellformed.py
# After copying rules onto a manager you operate (see tests/samples/README.md):
#   cat tests/samples/100013-ssh-root-success.log | /var/ossec/bin/wazuh-logtest
```

GitHub Actions runs the well-formedness, uniqueness, and ID-range checks on every push and pull request. Those checks do not replace `wazuh-logtest`.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 EmpowerU LLC.

Vulnerability reports: see [SECURITY.md](SECURITY.md) and bravo1alpha95@gmail.com.
