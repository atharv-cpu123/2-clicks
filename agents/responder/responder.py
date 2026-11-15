
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

from cryptography import x509


PROJECT_ROOT = Path(__file__).resolve().parents[2]

CERT_ROOT = (PROJECT_ROOT / "sandbox" / "certificates").resolve()

CA_CERTIFICATE = PROJECT_ROOT / "sandbox" / "ca" / "certs" / "intermediate_ca.crt"

RISK_REPORT = (
    PROJECT_ROOT
    / "agents"
    / "risk-analyst"
    / "reports"
    / "risk_report.json"
)

OUTPUT_DIR = PROJECT_ROOT / "agents" / "responder" / "reports"
PLAN_FILE = OUTPUT_DIR / "remediation_plan.json"

SEVERITY_PRIORITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


def load_risk_report():
    with open(RISK_REPORT, "r") as file:
        return json.load(file)


def load_local_ca():
    if not CA_CERTIFICATE.exists():
        raise FileNotFoundError(
            "Local intermediate CA certificate not found."
        )

    return x509.load_pem_x509_certificate(
        CA_CERTIFICATE.read_bytes()
    )


def inspect_certificate(path, local_ca):
    certificate_path = (PROJECT_ROOT / path).resolve()

    if not certificate_path.is_relative_to(CERT_ROOT):
        raise ValueError("Certificate path is outside the sandbox.")

    if not certificate_path.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {certificate_path}"
        )

    cert = x509.load_pem_x509_certificate(
        certificate_path.read_bytes()
    )

    ca_issued = cert.issuer == local_ca.subject

    return {
        "serial_number": format(cert.serial_number, "X"),
        "issuer": cert.issuer.rfc4514_string(),
        "ca_issued": ca_issued,
        "revocation_eligible": ca_issued
    }


def group_findings(findings):
    grouped = defaultdict(list)

    for finding in findings:
        certificate = finding.get("certificate")

        if certificate:
            grouped[certificate].append(finding)

    return grouped


def determine_priority(findings):
    return max(
        (
            item.get("severity", "LOW").upper()
            for item in findings
        ),
        key=lambda severity: SEVERITY_PRIORITY.get(severity, 0)
    )


def create_remediation_item(certificate, findings, local_ca):

    path = findings[0].get("path")

    certificate_info = inspect_certificate(path, local_ca)

    severity = determine_priority(findings)

    if certificate_info["revocation_eligible"]:
        proposed_action = (
            "Request approval for local CA revocation, "
            "then plan certificate reissuance."
        )
    else:
        proposed_action = (
            "Local CA revocation is not applicable. "
            "Investigate the issuing authority and remediate "
            "the certificate through the appropriate process."
        )

    return {
        "certificate": certificate,
        "path": path,
        "severity": severity,
        "total_issues": len(findings),

        **certificate_info,

        "issues": [
            {
                "code": item.get("code"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "description": item.get("description"),
                "evidence": item.get("evidence"),
                "recommendation": item.get("recommendation")
            }
            for item in findings
        ],

        "proposed_action": proposed_action,
        "approval_required": True,
        "approval_status": "PENDING",
        "remediation_status": "NOT_STARTED"
    }


def create_remediation_plan(report, local_ca):

    findings = report.get("prioritized_findings", [])
    grouped = group_findings(findings)

    # Preserve a human decision only for the exact same certificate serial.
    # A replaced/reissued certificate has a new serial and requires fresh review.
    previous_items = {}
    if PLAN_FILE.is_file():
        try:
            previous_plan = json.loads(PLAN_FILE.read_text(encoding="utf-8"))
            previous_items = {
                (item.get("certificate"), item.get("serial_number")): item
                for item in previous_plan.get("remediation_items", [])
            }
        except (OSError, json.JSONDecodeError):
            previous_items = {}

    items = []

    for certificate, certificate_findings in grouped.items():
        item = create_remediation_item(
            certificate,
            certificate_findings,
            local_ca
        )
        previous = previous_items.get((certificate, item["serial_number"]))
        if previous:
            for field in (
                "approval_required", "approval_status", "approval_decision",
                "approval_scope", "approval_timestamp", "approval_reason",
                "approved_by", "remediation_status",
            ):
                if field in previous:
                    item[field] = previous[field]
        items.append(item)

    items.sort(
        key=lambda item: SEVERITY_PRIORITY.get(
            item["severity"], 0
        ),
        reverse=True
    )

    severity_summary = {
        severity: sum(
            1 for item in items
            if item["severity"] == severity
        )
        for severity in SEVERITY_PRIORITY
    }

    return {
        "plan_id": datetime.now(timezone.utc).strftime(
            "REMEDIATION-%Y%m%d-%H%M%S"
        ),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_analysis_id": report.get("analysis_id"),
        "total_findings_reviewed": len(findings),
        "unique_certificates": len(items),
        "ca_issued_certificates": sum(
            1 for item in items if item["ca_issued"]
        ),
        "not_ca_issued_certificates": sum(
            1 for item in items if not item["ca_issued"]
        ),
        "revocation_eligible_certificates": sum(
            1 for item in items if item["revocation_eligible"]
        ),
        "severity_summary": severity_summary,
        "approval_required": True,
        "remediation_items": items
    }


def save_plan(plan):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(PLAN_FILE, "w") as file:
        json.dump(plan, file, indent=4)


def main():

    print("\n========== PKI RESPONDER AGENT ==========\n")

    try:
        report = load_risk_report()
        local_ca = load_local_ca()

        print("[SUCCESS] Risk report loaded.")
        print("[SUCCESS] Local CA certificate loaded.")

        plan = create_remediation_plan(report, local_ca)

        save_plan(plan)

        print("\n========== REMEDIATION SUMMARY ==========\n")

        print("Findings reviewed:", plan["total_findings_reviewed"])
        print("Unique certificates:", plan["unique_certificates"])
        print("CA-issued:", plan["ca_issued_certificates"])
        print("Not CA-issued:", plan["not_ca_issued_certificates"])
        print(
            "Revocation eligible:",
            plan["revocation_eligible_certificates"]
        )

        print("\n========== PRIORITIZED PLAN ==========\n")

        for index, item in enumerate(
            plan["remediation_items"], start=1
        ):
            print(
                f"{index}. {item['certificate']} "
                f"[{item['severity']}]"
            )

            print("   Serial:", item["serial_number"])
            print("   CA-issued:", item["ca_issued"])
            print(
                "   Revocation eligible:",
                item["revocation_eligible"]
            )
            print("   Issues:", item["total_issues"])
            print("   Approval:", item["approval_status"])
            print()

        print("[SECURITY] No certificates were modified or revoked.")
        print("[SECURITY] Human approval is mandatory.")
        print("\nPlan saved to:", PLAN_FILE)

    except Exception as error:
        print("[ERROR] Responder failed:", error)


if __name__ == "__main__":
    main()
