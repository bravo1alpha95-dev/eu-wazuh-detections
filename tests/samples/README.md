# Synthetic log samples — eu-wazuh-detections

These lines are **synthetic**. Source IPs are from the documentation range 203.0.113.0/24 ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)). Host and user names are placeholders. They exist so you can run `wazuh-logtest` against a manager **you operate**.

## How to run

On a Wazuh manager 4.14.x that already has `rules/eu_ec_detect_rules.xml` in `/var/ossec/etc/rules/` (and has been reloaded):

```bash
# Single-line samples (one event, one session)
cat tests/samples/100013-ssh-root-success.log | /var/ossec/bin/wazuh-logtest

# Frequency / correlation samples must be one session (pipe the whole file)
cat tests/samples/session-100016-100017-invalid-user.log | /var/ossec/bin/wazuh-logtest
```

From the official container, after mounting this repository:

```bash
docker run -d --name eu-wazuh-logtest -e TZ=America/New_York \
  -v "$PWD/rules/eu_ec_detect_rules.xml:/var/ossec/etc/rules/eu_ec_detect_rules.xml:ro" \
  -v "$PWD/decoders/eu_ec_detect_decoders.xml:/var/ossec/etc/decoders/eu_ec_detect_decoders.xml:ro" \
  wazuh/wazuh-manager:4.14.10
# wait until ossec.log says "Logtest started"
docker exec -i eu-wazuh-logtest /var/ossec/bin/wazuh-logtest < tests/samples/100013-ssh-root-success.log
```

`<time>` rules (100012, 100018) use the **manager's local clock**, not the timestamp in the log. To exercise the 00:00–05:00 window, set `TZ` so the manager's local time falls in that range.

The FIM `.json` samples are the agent event format documented in Wazuh 4.x. On 4.14.10, `wazuh-logtest` does **not** invoke the FIM plugin decoder (`syscheck_integrity_changed`), so those samples will not produce rule 550 / 100020 / 100021 through logtest. They are included as a reference for a live syscheck event.

Results from the 2026-11-13 run against `wazuh/wazuh-manager:4.14.10` are in [docs/LOGTEST.md](../../docs/LOGTEST.md).
