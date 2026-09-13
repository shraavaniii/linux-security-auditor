import subprocess
import json
import re
from datetime import datetime, timezone

result = subprocess.run(
    ["./audit.sh"],
    capture_output=True,
    text=True
)

output = result.stdout

findings = []

for line in output.splitlines():
    match = re.match(r"\[(PASS|INFO|WARN|CRITICAL)\]\s+(\S+)\s+\|\s+(.*)", line)

    if match:
        severity, finding_id, message = match.groups()

        findings.append({
            "severity": severity,
            "finding_id": finding_id,
            "message": message
        })

summary_match = re.search(
    r"PASS\s+:\s+(\d+).*?"
    r"INFO\s+:\s+(\d+).*?"
    r"WARN\s+:\s+(\d+).*?"
    r"CRITICAL\s+:\s+(\d+).*?"
    r"Risk Score\s+:\s+(\d+)/100.*?"
    r"Risk Level\s+:\s+(\w+)",
    output,
    re.S
)

if summary_match:
    pass_count, info_count, warn_count, critical_count, risk_score, risk_level = summary_match.groups()

    summary = {
        "pass": int(pass_count),
        "info": int(info_count),
        "warn": int(warn_count),
        "critical": int(critical_count),
        "risk_score": int(risk_score),
        "risk_level": risk_level
    }
else:
    summary = {}

report = {
    "tool": "Linux Security Auditor",
    "version": "1.0",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "summary": summary,
    "findings": findings
}

with open("audit_report.json", "w") as file:
    json.dump(report, file, indent=4)

print("JSON report generated: audit_report.json")
