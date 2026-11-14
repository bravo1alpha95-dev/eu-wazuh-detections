#!/usr/bin/env python3
"""Convert every EmpowerU Sigma rule with pySigma, deterministically.

pySigma 1.5.1 converts a correlation rule from its base rules' conversion
results, so base rules must be converted first. sigma-cli loads rules in
filesystem order, which differs between machines, so this script loads
non-correlation rules first, then correlations.

Usage:
  python3 sigma/tests/convert_all.py                 # check all targets
  python3 sigma/tests/convert_all.py --print splunk  # print queries for one target
Targets: splunk, splunk-raw (with pipelines/splunk_linux_raw.yml), esql, lucene.
Lucene has no correlation support, so correlation rules are skipped there.
"""
import argparse
import pathlib
import sys

from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline

SIGMA = pathlib.Path(__file__).resolve().parents[1]
RULES = SIGMA / "rules"


def ordered_files(include_correlations=True):
    files = sorted(RULES.glob("*.yml"))
    plain = [f for f in files if "\ncorrelation:" not in "\n" + f.read_text(encoding="utf-8")]
    corr = [f for f in files if f not in plain]
    return plain + (corr if include_correlations else [])


def backend_for(target):
    if target == "splunk":
        return SplunkBackend()
    if target == "splunk-raw":
        pipe = ProcessingPipeline.from_yaml(
            (SIGMA / "pipelines" / "splunk_linux_raw.yml").read_text(encoding="utf-8"))
        return SplunkBackend(processing_pipeline=pipe)
    if target == "esql":
        return ESQLBackend()
    if target == "lucene":
        return LuceneBackend()
    raise SystemExit(f"unknown target {target}")


def convert(target):
    """Return {file name: [queries]} for one target.

    Non-correlation rules (including the base rules) are converted in a
    collection of their own, because pySigma suppresses standalone output
    for rules referenced by a correlation. Correlations are then converted
    from the full, base-first collection.
    """
    backend = backend_for(target)
    results = {}
    for rule in SigmaCollection.load_ruleset(ordered_files(include_correlations=False)):
        results[rule.source.path.name] = [q for q in backend.convert_rule(rule) if str(q).strip()]
    if target != "lucene":
        backend = backend_for(target)
        for rule in SigmaCollection.load_ruleset(ordered_files()):
            if isinstance(rule, SigmaCorrelationRule):
                queries = backend.convert_correlation_rule(rule)
                results[rule.source.path.name] = [q for q in queries if str(q).strip()]
            else:
                backend.convert_rule(rule)  # base results feed the correlations
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--print", dest="show", metavar="TARGET")
    args = ap.parse_args()
    if args.show:
        for name, queries in convert(args.show).items():
            print(f"# {name}")
            print("\n".join(str(q) for q in queries) + "\n")
        return 0

    total = len(ordered_files())
    plain = len(ordered_files(include_correlations=False))
    expected = {"splunk": total, "splunk-raw": total, "esql": total, "lucene": plain}
    failed = False
    for target, want in expected.items():
        res = convert(target)
        ok = sorted(n for n, q in res.items() if q)
        print(f"== {target}: {len(ok)}/{want} rules converted")
        if len(ok) != want:
            failed = True
            print(f"FAIL: missing {sorted(set(res) - set(ok))}")
    raw = convert("splunk-raw")["eu_100013_ssh_root_login.yml"][0]
    if "_raw=" not in str(raw):
        failed = True
        print("FAIL: splunk_linux_raw pipeline did not map message to _raw")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
