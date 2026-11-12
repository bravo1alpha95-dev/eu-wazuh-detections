# Contributing to eu-wazuh-detections

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

- Keep rule IDs in the 100000+ custom range and do not reuse an ID.
- Add or update a row in [docs/RULE-MAP.md](docs/RULE-MAP.md) for every rule change.
- Attach a MITRE ATT&CK ID only when the mapping is clearly accurate. Prefer omitting an ID to stretching one.
- Use synthetic log lines in any example. No production alerts, addresses, or secrets.
- Run `python3 tests/test_xml_wellformed.py` before opening a pull request.
- This pack is defensive only and is for systems the operator owns.

Security issues: [SECURITY.md](SECURITY.md).
