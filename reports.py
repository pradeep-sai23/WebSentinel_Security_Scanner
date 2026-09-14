import json
import os
from datetime import datetime


def save_report(
    target,
    findings,
    critical,
    high,
    medium,
    low,
    risk
):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = f"reports/scan_{timestamp}.json"

    report = {
        "scanner": "WebSentinel",
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "summary": {
            "total_findings": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "overall_risk": risk
        },
        "findings": findings
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4
        )

    return filename
