#!/usr/bin/env python3
"""Well-formedness, ID-range, and uniqueness checks for Wazuh XML and the starter dashboard."""
import json
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = list((ROOT / "rules").glob("*.xml"))
DECODERS = list((ROOT / "decoders").glob("*.xml"))
DASHBOARD = ROOT / "dashboards/eu-ec-detect-starter.ndjson"


class XmlPack(unittest.TestCase):
    def test_xml_well_formed(self):
        files = RULES + DECODERS
        self.assertTrue(files, "no XML files found")
        for path in files:
            with self.subTest(path=path.name):
                ET.parse(path)

    def test_rule_ids_unique_and_custom_range(self):
        ids = []
        for path in RULES:
            text = path.read_text(encoding="utf-8")
            ids.extend(int(m) for m in re.findall(r'<rule\b[^>]*\bid="(\d+)"', text))
        self.assertTrue(ids, "no rule IDs found")
        self.assertEqual(len(ids), len(set(ids)), f"duplicate rule IDs: {ids}")
        for rid in ids:
            self.assertGreaterEqual(rid, 100000, rid)
            self.assertLess(rid, 120000, rid)

    def test_rule_map_lists_every_rule(self):
        ids = set()
        for path in RULES:
            ids.update(int(m) for m in re.findall(r'<rule\b[^>]*\bid="(\d+)"', path.read_text(encoding="utf-8")))
        mapping = (ROOT / "docs/RULE-MAP.md").read_text(encoding="utf-8")
        missing = [rid for rid in sorted(ids) if not re.search(rf"\|\s*{rid}\s*\|", mapping)]
        self.assertEqual(missing, [], f"RULE-MAP.md missing IDs: {missing}")

    def test_mitre_ids_look_like_attack(self):
        for path in RULES:
            text = path.read_text(encoding="utf-8")
            for mid in re.findall(r"<id>(T\d+(?:\.\d+)?)</id>", text):
                self.assertRegex(mid, r"^T\d{4}(\.\d{3})?$")

    def test_starter_dashboard_ndjson(self):
        lines = [ln for ln in DASHBOARD.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertGreaterEqual(len(lines), 3)
        types = []
        for ln in lines:
            obj = json.loads(ln)
            self.assertIn("id", obj)
            self.assertIn("type", obj)
            types.append(obj["type"])
        self.assertIn("dashboard", types)
        self.assertIn("visualization", types)
        self.assertIn("index-pattern", types)
        raw = DASHBOARD.read_text(encoding="utf-8").lower()
        self.assertIn("untested", raw)
        self.assertIn("starter", raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
