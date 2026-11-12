# Security Considerations — eu-wazuh-detections

Defensive Wazuh rules for **systems you own**. This pack has not been tested with `wazuh-logtest` against a live manager.

## Reporting vulnerabilities

Please report security issues privately to **[CONTACT EMAIL]**. Do not open a public issue for a vulnerability, and do not attach production alerts, secrets, or personally identifiable information.

## Operator responsibilities

- Confirm parent rule IDs on your Wazuh version before enabling these rules.
- Tune frequencies, time windows, and match lists so they match your baseline. Untuned "unusual hours" and "multiple failures" rules will produce noise or miss events.
- Default Wazuh already includes some SSH and PAM correlation. Review for duplicate alerts.
- Treat the dashboard export as a starter, not a finished detection operation view.
- Do not use these rules to monitor systems you do not own.

## Residual risks

- False positives from broad process matches (`python -m http`, `busybox`) on hosts where those tools are legitimate.
- False negatives when logs are not decoded by the assumed default decoders, or when parent SIDs have changed.
- File-integrity rules fire on any matching path change, including authorized patching.
- Same-source correlation depends on the manager correctly parsing a source IP.
