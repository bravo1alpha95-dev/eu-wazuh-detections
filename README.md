# eu-wazuh-detections

Wazuh custom rules, optional decoders, and a **starter** dashboard derived from EmpowerU LLC's community access-monitoring toolkit ([eu-ec-detect-community](https://github.com/bravo1alpha95-dev/eu-ec-detect-community)).

**Defensive only. Owned systems only.** This pack does not include offensive detections, exploit content, or targeting of third-party systems.

## Not tested on a live manager

`wazuh-logtest` was not available when this pack was published, and the rules have **not** been tested against a live Wazuh manager. Parent rule IDs come from default Wazuh rule sets and can vary by version. Validate every rule with `wazuh-logtest` on your manager, and tune thresholds, hours, and match lists to your baseline, before you rely on the alerts.

The dashboard export is a starter. It is untested and may need adjustments for your Wazuh and OpenSearch Dashboards versions. See [dashboards/README.md](dashboards/README.md).

## Contents

| Path | What it is |
|---|---|
| [rules/eu_ec_detect_rules.xml](rules/eu_ec_detect_rules.xml) | Custom rules, IDs in the 100000+ range |
| [docs/RULE-MAP.md](docs/RULE-MAP.md) | Each rule, what it detects, and MITRE ATT&CK IDs (only where clearly accurate) |
| [decoders/eu_ec_detect_decoders.xml](decoders/eu_ec_detect_decoders.xml) | Optional classifier for collector JSON; the rules do not depend on it |
| [dashboards/eu-ec-detect-starter.ndjson](dashboards/eu-ec-detect-starter.ndjson) | Starter saved-object export (untested) |
| [examples/ossec-agent-snippets.conf](examples/ossec-agent-snippets.conf) | Optional agent FIM and manager-address snippets |

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
4. On the manager, run `wazuh-logtest` against representative log lines for your Wazuh version. Confirm parent SIDs (`530`, `550`, `5501`, `5503`, `5710`, `5715`) still mean what this pack assumes.
5. Restart or reload the manager only after that review, and only on a system you own, under your own change control.

The [eu-monitor-installer](https://github.com/bravo1alpha95-dev/eu-monitor-installer) Ansible role can perform the copy in check mode (`--check`) first.

Do not paste unreviewed production alerts into public issues.

## Checks

```bash
python3 tests/test_xml_wellformed.py
```

GitHub Actions runs the same well-formedness check, plus a uniqueness and ID-range check, on every push and pull request.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 EmpowerU LLC.

Vulnerability reports: see [SECURITY.md](SECURITY.md) and `[CONTACT EMAIL]`.
