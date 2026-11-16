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
        """Structure checks for the starter dashboard (Saved Objects ndjson).

        The file was imported into Wazuh dashboard 4.14.10 (OpenSearch
        Dashboards 2.19.6) on 2026-11-14. That import rejected the original
        migrationVersion "8.0.0" ("belongs to a more recent version"), so this
        test keeps every migrationVersion at or below what OSD 2.x knows, and
        checks that every reference resolves inside the file.
        """
        lines = [ln for ln in DASHBOARD.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertGreaterEqual(len(lines), 3)
        objs = [json.loads(ln) for ln in lines]
        ids = {(o["type"], o["id"]) for o in objs}
        self.assertEqual(len(ids), len(objs), "duplicate saved-object type/id")
        types = [o["type"] for o in objs]
        self.assertIn("dashboard", types)
        self.assertIn("visualization", types)
        self.assertIn("index-pattern", types)
        max_known = {"index-pattern": (7, 6, 0), "visualization": (7, 10, 0), "dashboard": (7, 9, 3)}
        for o in objs:
            with self.subTest(obj=o["id"]):
                for typ, ver in (o.get("migrationVersion") or {}).items():
                    parts = tuple(int(x) for x in ver.split("."))
                    self.assertLessEqual(parts, max_known.get(typ, (7, 10, 2)), f"{typ} migrationVersion {ver} too new for OSD 2.x")
                refs = o.get("references", [])
                names = [r["name"] for r in refs]
                self.assertEqual(len(names), len(set(names)), "duplicate reference names")
                for r in refs:
                    self.assertIn((r["type"], r["id"]), ids, f"dangling reference {r}")
                attrs = o["attributes"]
                if o["type"] == "visualization":
                    ss = json.loads(attrs["kibanaSavedObjectMeta"]["searchSourceJSON"])
                    self.assertIn(ss.get("indexRefName"), names)
                    json.loads(attrs["visState"])
                if o["type"] == "dashboard":
                    for panel in json.loads(attrs["panelsJSON"]):
                        self.assertIn(panel.get("panelRefName"), names)
        raw = DASHBOARD.read_text(encoding="utf-8").lower()
        self.assertIn("starter", raw)
        self.assertIn("tested 2026-11-14", raw)

if __name__ == "__main__":
    unittest.main(verbosity=2)
