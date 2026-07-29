import json
from pathlib import Path

REPORT = Path("reports/report.json")

if not REPORT.exists():
    raise FileNotFoundError("report.json not found")

with REPORT.open("r", encoding="utf-8") as f:
    data = json.load(f)

summary = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}

findings = []

for site in data.get("site", []):

    for alert in site.get("alerts", []):

        risk = alert.get("riskdesc", "Unknown").split()[0]

        summary[risk] = summary.get(risk, 0) + 1

        findings.append(
            {
                "title": alert.get("name"),
                "risk": risk,
                "confidence": alert.get("confidence"),
                "description": alert.get("desc"),
                "solution": alert.get("solution"),
                "reference": alert.get("reference"),
                "instances": [
                    {"url": instance.get("uri"), "method": instance.get("method")}
                    for instance in alert.get("instances", [])
                ],
            }
        )

print("=" * 60)
print("OWASP ZAP Scan Summary")
print("=" * 60)

for level, count in summary.items():
    print(f"{level:15}: {count}")

print("=" * 60)
print(f"Total Findings : {len(findings)}")
print("=" * 60)
