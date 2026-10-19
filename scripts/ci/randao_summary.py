"""Validate complete vector accounting and publish the GitHub Actions summary."""
import csv
import os
from collections import Counter
from pathlib import Path

root = Path(__file__).resolve().parents[2]
expected = {
    "minimal": {"PASS": 826, "PROPERTY_PASS": 1, "OUT_OF_SCOPE": 621},
    "mainnet": {"PASS": 751, "PROPERTY_PASS": 1, "OUT_OF_SCOPE": 400},
}
lines = ["## EIP-8321 consensus state-transition results", "",
         f"Commit: `{os.environ.get('GITHUB_SHA', 'local')}`", "",
         "| Preset | Vector cases passed | Local properties passed | Client/network outside scope |",
         "| --- | ---: | ---: | ---: |"]
errors = []
for preset, counts in expected.items():
    path = root / "test-vectors" / "reports" / f"all-{preset}.tsv"
    if not path.is_file():
        errors.append(f"Missing report: {path.name}")
        continue
    with path.open(newline="") as report:
        rows = list(csv.DictReader(report, delimiter="\t"))
    actual = Counter(row["status"] for row in rows)
    if actual != Counter(counts):
        errors.append(f"{preset}: expected {counts}, got {dict(actual)}")
    if len({row["case"] for row in rows}) != len(rows):
        errors.append(f"{preset}: duplicate fixture cases")
    lines.append(f"| {preset} | {actual['PASS']} | {actual['PROPERTY_PASS']} | {actual['OUT_OF_SCOPE']} |")
lines += ["", "Pinned EIP-8321 source: `12c8b24bc09b12f62688d439ba20ef00b1fdfe1f`.",
          "", "The 1,577 vector cases cover operations, epochs, rewards, slots, blocks, finality and Heze → EIP-8321 upgrades.",
          "Two upstream manifest-only properties are executed separately; 1,021 client/network manifests are not claimed as passing.",
          "The upstream mainnet lifecycle generator fails its 256 <= 128 assertion and produced no lifecycle fixture.",
          "", "Local unit tests and feature-off legacy regressions are separate required workflow steps.",
          "See the eip8321-results artifact for TSV reports and complete test logs."]
if errors:
    lines += ["", "**Report validation failed:**", ""] + [f"- {error}" for error in errors]
else:
    lines += ["", "**All 1,577 available consensus vector cases passed.**"]
summary = "\n".join(lines) + "\n"
print(summary)
if destination := os.environ.get("GITHUB_STEP_SUMMARY"):
    with Path(destination).open("a") as output:
        output.write(summary)
if errors:
    raise SystemExit(1)
