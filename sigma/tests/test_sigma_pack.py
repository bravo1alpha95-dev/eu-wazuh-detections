#!/usr/bin/env python3
"""Structural checks for the EmpowerU Sigma pack (stdlib + PyYAML only).

Checks every Wazuh rule in rules/eu_ec_detect_rules.xml has exactly one Sigma
port, every Sigma file has the required metadata and a unique UUID, and the
README mapping table lists each port.
"""
import pathlib
import re
import sys
import uuid
import xml.etree.ElementTree as ET

import yaml

SIGMA = pathlib.Path(__file__).resolve().parents[1]
REPO = SIGMA.parent
RULES = SIGMA / "rules"
REQUIRED = ("title", "id", "status", "description", "references", "author",
            "date", "level", "falsepositives")
LEVELS = {"informational", "low", "medium", "high", "critical"}


def wazuh_ids():
    text = (REPO / "rules" / "eu_ec_detect_rules.xml").read_text(encoding="utf-8")
    root = ET.fromstring("<root>" + re.sub(r"<\?xml[^>]*\?>", "", text) + "</root>")
    return sorted(r.get("id") for r in root.iter("rule"))


# Synthetic samples (tests/samples/) that each message-based rule must match.
SAMPLE_MATCHES = {
    "eu_base_pam_auth_failure.yml": ["5503-pam-failure.log"],
    "eu_base_pam_session_opened.yml": ["100012-pam-success.log"],
    "eu_100012_pam_offhours_login.yml": ["100012-pam-success.log"],
    "eu_base_ssh_failed_auth.yml": ["5760-ssh-failed-password.log", "5710-ssh-invalid-user.log"],
    "eu_base_ssh_auth_success.yml": ["100013-ssh-root-success.log", "100018-ssh-user-success.log"],
    "eu_100018_ssh_offhours_login.yml": ["100018-ssh-user-success.log"],
    "eu_100013_ssh_root_login.yml": ["100013-ssh-root-success.log"],
}
# Samples that must NOT match (PAM success vs failure must stay distinct).
SAMPLE_NON_MATCHES = {
    "eu_base_pam_auth_failure.yml": ["100012-pam-success.log"],
    "eu_base_pam_session_opened.yml": ["5503-pam-failure.log"],
    "eu_100013_ssh_root_login.yml": ["100018-ssh-user-success.log"],
}


def message_matches(rule, line):
    """Evaluate a single-selection rule on message|contains / contains|all."""
    sel = rule["detection"]["selection"]
    for key, vals in sel.items():
        vals = vals if isinstance(vals, list) else [vals]
        if key == "message|contains|all":
            if not all(v in line for v in vals):
                return False
        elif key == "message|contains":
            if not any(v in line for v in vals):
                return False
        else:
            raise ValueError(f"unsupported key {key}")
    return True


def check_samples(errors):
    samples = REPO / "tests" / "samples"
    for table, want in ((SAMPLE_MATCHES, True), (SAMPLE_NON_MATCHES, False)):
        for fname, sample_files in table.items():
            rule = yaml.safe_load((RULES / fname).read_text(encoding="utf-8"))
            for sf in sample_files:
                line = (samples / sf).read_text(encoding="utf-8").splitlines()[0]
                if message_matches(rule, line) != want:
                    errors.append(f"{fname}: expected match={want} on {sf}")


def main():
    errors = []
    files = sorted(RULES.glob("*.yml"))
    if not files:
        errors.append("no Sigma rules found")
    ids, names, ports = {}, {}, {}
    for f in files:
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        for key in REQUIRED:
            if key not in doc:
                errors.append(f"{f.name}: missing {key}")
        if doc.get("status") != "experimental":
            errors.append(f"{f.name}: status must be experimental")
        if doc.get("level") not in LEVELS:
            errors.append(f"{f.name}: bad level {doc.get('level')}")
        try:
            uuid.UUID(str(doc.get("id")))
        except ValueError:
            errors.append(f"{f.name}: id is not a UUID")
        if doc.get("id") in ids:
            errors.append(f"{f.name}: duplicate id with {ids[doc['id']]}")
        ids[doc.get("id")] = f.name
        if "correlation" in doc:
            for ref in doc["correlation"]["rules"]:
                names.setdefault("__refs__", set()).add(ref)
        elif "logsource" not in doc or "detection" not in doc:
            errors.append(f"{f.name}: needs logsource and detection")
        if doc.get("name"):
            names[doc["name"]] = f.name
        m = re.match(r"eu_(1\d{5})_", f.name)
        if m:
            ports.setdefault(m.group(1), []).append(f.name)
            if m.group(1) not in doc.get("title", ""):
                errors.append(f"{f.name}: title must name Wazuh rule {m.group(1)}")
        text = f.read_text(encoding="utf-8")
        if re.search(r"\b172\.29\.", text):
            errors.append(f"{f.name}: contains a lab address")
    for ref in names.pop("__refs__", set()):
        if ref not in names:
            errors.append(f"correlation references unknown rule name {ref}")

    readme = (SIGMA / "README.md").read_text(encoding="utf-8")
    for wid in wazuh_ids():
        got = ports.get(wid, [])
        if len(got) != 1:
            errors.append(f"Wazuh rule {wid}: expected 1 Sigma port, found {got}")
        else:
            row = re.search(rf"^\|\s*{wid}\s*\|.*{re.escape(got[0])}", readme, re.M)
            if not row:
                errors.append(f"README mapping table missing {wid} -> {got[0]}")
    extra = set(ports) - set(wazuh_ids())
    if extra:
        errors.append(f"Sigma ports for unknown Wazuh IDs: {sorted(extra)}")

    check_samples(errors)

    if errors:
        print("\n".join("FAIL: " + e for e in errors))
        return 1
    print(f"OK: {len(files)} Sigma files, {len(ports)} Wazuh rules mapped, UUIDs unique")
    return 0


if __name__ == "__main__":
    sys.exit(main())
