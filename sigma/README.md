# Sigma rules — eu-wazuh-detections

[Sigma](https://sigmahq.io/) ports of the EmpowerU Wazuh rules in [`rules/eu_ec_detect_rules.xml`](../rules/eu_ec_detect_rules.xml). Sigma is a vendor-neutral rule format that converts to Splunk, Elasticsearch, Microsoft Sentinel, and other SIEM query languages with [pySigma / sigma-cli](https://github.com/SigmaHQ/sigma-cli).

**Defensive only. Owned systems only.** Every rule is `status: experimental`. The Wazuh rules were verified on Wazuh 4.14.10; these Sigma ports were linted and **test-converted** only. They have not been run against live Splunk or Elasticsearch data. Tune them on your own logs before you rely on them.

## Mapping table

| Wazuh ID | Sigma file | Type | Notes |
|---|---|---|---|
| 100002 | [eu_100002_unexpected_listener_process.yml](rules/eu_100002_unexpected_listener_process.yml) | `process_creation` / linux | `nc`, `ncat`, `socat`, `busybox`, `python -m http`. Uses process-creation events instead of Wazuh process-monitoring output (530) |
| 100010 | [eu_100010_pam_failed_login_burst.yml](rules/eu_100010_pam_failed_login_burst.yml) | `event_count` correlation | 8 PAM failures in 180 s by `host` + `rhost` (Wazuh default 5551 over 5503) |
| 100011 | [eu_100011_pam_success_after_failures.yml](rules/eu_100011_pam_success_after_failures.yml) | `temporal` correlation | PAM failure + PAM session opened on one `host` in 180 s. **Broader than Wazuh**, see below |
| 100012 | [eu_100012_pam_offhours_login.yml](rules/eu_100012_pam_offhours_login.yml) | linux / `auth` | PAM session opened (5501). **00:00–05:00 window must be applied in the SIEM** |
| 100013 | [eu_100013_ssh_root_login.yml](rules/eu_100013_ssh_root_login.yml) | linux / `sshd` | `Accepted ... for root from` (5715 + user root) |
| 100016 | [eu_100016_ssh_failed_login_burst.yml](rules/eu_100016_ssh_failed_login_burst.yml) | `event_count` correlation | 8 SSH failures (`Failed password`, `Invalid user`) in 120 s by `host` + `src_ip` (Wazuh 5712 / 5763) |
| 100017 | [eu_100017_ssh_success_after_failures.yml](rules/eu_100017_ssh_success_after_failures.yml) | `temporal` correlation | SSH failure + SSH success from one `src_ip` in 180 s. **Broader than Wazuh**, see below |
| 100018 | [eu_100018_ssh_offhours_login.yml](rules/eu_100018_ssh_offhours_login.yml) | linux / `sshd` | SSH success (5715). **00:00–05:00 window must be applied in the SIEM** |
| 100020 | [eu_100020_fim_critical_binary_modified.yml](rules/eu_100020_fim_critical_binary_modified.yml) | `file_change` / linux | Modified (Wazuh 550, not 554 "added") under `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/` |
| 100021 | [eu_100021_fim_ssh_sudo_policy_modified.yml](rules/eu_100021_fim_ssh_sudo_policy_modified.yml) | `file_change` / linux | Modified (550) `/etc/ssh/sshd_config*`, `/etc/sudoers*` (includes `/etc/sudoers.d/`) |

Base rules used by the correlations (they also convert on their own, at level `informational`):

| Base rule | Equivalent Wazuh default |
|---|---|
| [eu_base_pam_auth_failure.yml](rules/eu_base_pam_auth_failure.yml) | 5503, PAM authentication **failure** |
| [eu_base_pam_session_opened.yml](rules/eu_base_pam_session_opened.yml) | 5501, PAM session opened (**success**) |
| [eu_base_ssh_failed_auth.yml](rules/eu_base_ssh_failed_auth.yml) | 5760 "Failed password" and 5710 non-existent user |
| [eu_base_ssh_auth_success.yml](rules/eu_base_ssh_auth_success.yml) | 5715, sshd authentication success |

Levels follow the Wazuh levels: Wazuh 12 → `high`, 10 → `medium`, 8 → `low`. 100011 and 100017 are `medium` because the Sigma port is broader than the Wazuh rule.

## Differences from the Wazuh rules

- **Off-hours (100012, 100018).** Sigma has no time-of-day condition. These rules match every successful login. Add the hour filter in your SIEM, for example Splunk `| where date_hour < 5`, or an Elasticsearch rule that filters on the hour of `@timestamp` in your time zone. Wazuh uses the manager's local clock.
- **Success after failures (100011, 100017).** In Wazuh these fire only after burst rule 100010 / 100016 (8 failures). A chained Sigma correlation (a correlation that references another correlation) is valid Sigma, but the Splunk and ES|QL backends tested (pySigma 1.5.1) produced broken queries for it, and Splunk does not support `temporal_ordered`. The ports therefore use an unordered `temporal` correlation over the base failure and success rules: any failure plus a success in the same 180-second window. Pair them with 100010 / 100016 in your SIEM to match Wazuh.
- **100016 counting.** One attempt against a non-existent user can log both `Invalid user` and `Failed password for invalid user`, so the Sigma count can reach 8 sooner than Wazuh's 5712 / 5763.
- **FIM paths (100020, 100021).** Wazuh `<match>` is a substring match anywhere in the log; the Sigma ports use `startswith` on the file path, which is stricter (for example `/usr/local/bin/` matches the Wazuh rule but not the Sigma port).
- **100002.** Wazuh matches process-monitoring command output; the port uses process-creation telemetry (for example auditd `execve` or an EDR). Neither confirms a listening socket.

## Field names

The rules use Sigma taxonomy fields where they exist (`Image`, `CommandLine`, `TargetFilename`). Linux syslog has no standard Sigma fields, so the auth/sshd rules use:

| Field | Meaning | Elastic (Filebeat `system` module) | Splunk | Wazuh indexer |
|---|---|---|---|---|
| `message` | Raw syslog line | `message` | `_raw` (via the pipeline below) | `full_log` |
| `host` | Reporting host | `host.name` | `host` | `agent.name` |
| `rhost` | pam_unix `rhost=` value | needs parsing | auto key=value extraction | `data.srcip` |
| `src_ip` | SSH client address | `source.ip` | `src` (via the pipeline below) | `data.srcip` |

Map these to your schema with a pySigma processing pipeline. [`pipelines/splunk_linux_raw.yml`](pipelines/splunk_linux_raw.yml) maps `message` → `_raw` and `src_ip` → `src` for Splunk.

## Convert

```bash
python3 -m venv .venv-sigma && . .venv-sigma/bin/activate
pip install -r sigma/requirements.txt

sigma check sigma/rules
sigma convert -t splunk -p sigma/pipelines/splunk_linux_raw.yml sigma/rules
sigma convert -t esql --without-pipeline sigma/rules
# Lucene has no correlation support; -s skips the four correlation rules
sigma convert -t lucene --without-pipeline -s sigma/rules
```

`--without-pipeline` keeps the generic field names above; add your own pipeline for production.

## Validation

`sigma/validate.sh` runs the structural test (`sigma/tests/test_sigma_pack.py`: one port per Wazuh rule, unique UUIDs, required metadata, this mapping table), `sigma check --fail-on-issues`, and converts every rule to Splunk and ES|QL, plus every non-correlation rule to Lucene, failing on anything unsupported. GitHub Actions runs it on every push and pull request.

Results on 2026-11-14 (sigma-cli 3.1.0, pySigma 1.5.1, Splunk backend 2.1.0, Elasticsearch backend 2.1.1): 14 rules, 0 errors, 0 validation issues; Splunk 14/14, ES|QL 14/14, Lucene 10/10 non-correlation rules.

## License

Apache License 2.0, same as the rest of this repository.
