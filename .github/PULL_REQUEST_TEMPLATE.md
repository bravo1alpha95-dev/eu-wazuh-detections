## What this changes

## How it was tested

- [ ] `python3 tests/test_xml_wellformed.py` passes
- [ ] Rule IDs are unique and in the 100000+ range
- [ ] [docs/RULE-MAP.md](docs/RULE-MAP.md) is updated
- [ ] MITRE ATT&CK IDs are present only where clearly accurate
- [ ] No production alerts, secrets, or real addresses are included

Note whether you were able to run `wazuh-logtest` (this pack shipped untested against a live manager).
