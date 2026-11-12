# Starter dashboard (untested)

`eu-ec-detect-starter.ndjson` is a **starter** saved-object export for Wazuh Dashboard / OpenSearch Dashboards. It is clearly labeled untested.

- It has **not** been imported into a live manager in this project.
- The index pattern is `wazuh-alerts-*` with time field `timestamp`. Your cluster may use a different pattern or time field (`@timestamp`).
- Visualizations filter on the custom rule IDs in this pack (100002–100021).
- Import via the dashboard **Saved Objects** (or **Management → Saved Objects**) page, and expect to adjust object versions, index-pattern fields, and panel layout for your Wazuh and OpenSearch versions.

Do not treat a successful import as validation of the detection rules. Validate rules with `wazuh-logtest` on your manager.
