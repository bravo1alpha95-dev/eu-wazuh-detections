# Starter dashboard

`eu-ec-detect-starter.ndjson` is a **starter** saved-object export for the Wazuh dashboard (OpenSearch Dashboards). It has seven panels: failed-login bursts (100010, 100016), success after failures (100011, 100017), off-hours logins (100012, 100018), root SSH success (100013), unexpected listener processes (100002), FIM on critical and policy paths (100020, 100021), and a rule-ID breakdown.

## Tested

On 2026-11-14 (America/New_York) it was imported into `wazuh/wazuh-dashboard:4.14.10` (OpenSearch Dashboards 2.19.6) backed by `wazuh/wazuh-indexer:4.14.10`, in the Docker lab described in [docs/SETUP-WAZUH-LAB.md, step 6](../docs/SETUP-WAZUH-LAB.md#6-optional-add-the-indexer-and-dashboard). All 9 objects imported, and all seven panels rendered; six showed live EmpowerU alerts from the attack simulation. The off-hours panel was empty because the run was in the daytime. Screenshot: [docs/images/starter-dashboard.png](../docs/images/starter-dashboard.png).

The first import of the earlier version **failed** with `index-pattern ... belongs to a more recent version of OpenSearch Dashboards [8.0.0]`. The export now uses OpenSearch Dashboards 2.x migration versions and reference format, and the rule-breakdown pie has valid chart parameters. `tests/test_xml_wellformed.py` checks those properties so the problem cannot come back unnoticed.

Not tested: other Wazuh dashboard / OpenSearch Dashboards versions, and Kibana.

## Import

- Lab: `CONFIRM=yes lab/dashboard/dashboard.sh import`.
- Any Wazuh dashboard: **Dashboards Management → Saved objects → Import**, then choose this file.

The export brings its own index pattern (`wazuh-alerts-*`, time field `timestamp`, id `eu-ec-detect-starter-index-pattern`), next to the one the Wazuh app creates. If your alerts use a different pattern or time field, edit that index pattern after import.

A dashboard that shows alerts is not a test of the detection rules. Validate rules with `wazuh-logtest` on your manager and, for a live check, with [the attack simulation](../docs/ATTACK-SIMULATION.md).
