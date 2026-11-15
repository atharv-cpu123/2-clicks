
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCANNER_REPORT = (
    PROJECT_ROOT
    / "agents"
    / "scanner"
    / "reports"
    / "scan_report.json"
)

REPORT_DIR = Path(__file__).resolve().parent / "reports"
RISK_REPORT = REPORT_DIR / "risk_report.json"


# Risk weights used for health score calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 1
}


def load_scanner_report():
    if not SCANNER_REPORT.exists():
        raise FileNotFoundError(
            f"Scanner report not found: {SCANNER_REPORT}"
        )

    with SCANNER_REPORT.open("r", encoding="utf-8") as file:
        return json.load(file)


def calculate_health_score(certificates, findings):
    total_certificates = len(certificates)

    if total_certificates == 0:
        return 0, 0

    # Add a certificate's finding weights together, then cap its contribution.
    # This prevents several findings on one certificate from exceeding the
    # same 10-point maximum used by the denominator.
    risk_by_certificate = {}
    for finding in findings:
        certificate = finding.get("certificate", "unknown")
        weight = SEVERITY_WEIGHTS.get(
            finding.get("severity", "LOW").upper(), 0
        )
        risk_by_certificate[certificate] = (
            risk_by_certificate.get(certificate, 0) + weight
        )

    risk_points = sum(
        min(points, 10) for points in risk_by_certificate.values()
    )

    max_risk_points = total_certificates * 10

    risk_percentage = min(
        100,
        (risk_points / max_risk_points) * 100
    )

    health_score = round(100 - risk_percentage, 2)

    return health_score, risk_points


def prioritize_findings(certificates):
    prioritized = []

    for certificate in certificates:
        for finding in certificate.get("findings", []):
            prioritized.append({
                "certificate": certificate["certificate"],
                "path": certificate["path"],
                "severity": finding["severity"],
                "code": finding["code"],
                "title": finding["title"],
                "description": finding["description"],
                "evidence": finding["evidence"],
                "recommendation": finding["recommendation"]
            })

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    prioritized.sort(
        key=lambda item: severity_order.get(
            item["severity"], 4
        )
    )

    return prioritized


def generate_risk_summary(prioritized_findings):
    counts = Counter(
        finding["severity"]
        for finding in prioritized_findings
    )

    return {
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "total": len(prioritized_findings)
    }


def main():
    print("\n========== PKI RISK ANALYST ==========\n")

    scanner_data = load_scanner_report()

    certificates = scanner_data.get("certificates", [])

    findings = prioritized_findings = prioritize_findings(
        certificates
    )

    health_score, risk_points = calculate_health_score(
        certificates,
        findings
    )

    summary = generate_risk_summary(prioritized_findings)

    if health_score >= 90:
        health_status = "HEALTHY"
    elif health_score >= 70:
        health_status = "MODERATE RISK"
    elif health_score >= 40:
        health_status = "HIGH RISK"
    else:
        health_status = "CRITICAL RISK"

    report = {
        "analysis_id": datetime.now(
            timezone.utc
        ).strftime("RISK-%Y%m%d-%H%M%S"),
        "analyzed_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "source_scan_id": scanner_data.get("scan_id"),
        "certificates_analyzed": len(certificates),
        "health_score": health_score,
        "health_status": health_status,
        "risk_points": risk_points,
        "scoring_formula": {
            "description": (
                "Per certificate, add finding weights and cap at 10. "
                "Health Score = 100 - "
                "(Capped Risk Points / (Certificate Count * 10)) * 100"
            ),
            "maximum_risk_points_per_certificate": 10,
            "per_certificate_cap": 10,
            "severity_weights": SEVERITY_WEIGHTS
        },
        "summary": summary,
        "prioritized_findings": prioritized_findings
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with RISK_REPORT.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"Certificates analyzed: {len(certificates)}")
    print(f"Total findings: {summary['total']}")
    print(f"Critical: {summary['critical']}")
    print(f"High: {summary['high']}")
    print(f"Medium: {summary['medium']}")
    print(f"Low: {summary['low']}")

    print("\n========== PKI HEALTH ==========")
    print(f"Health Score: {health_score}/100")
    print(f"Health Status: {health_status}")
    print(f"Total Risk Points: {risk_points}")

    print(f"\nRisk report saved to: {RISK_REPORT}")


if __name__ == "__main__":
    main()
