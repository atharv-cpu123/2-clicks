
import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = (PROJECT_ROOT / "sandbox" / "certificates").resolve()

REPORT_DIR = PROJECT_ROOT / "agents" / "responder" / "reports"
PLAN_FILE = REPORT_DIR / "remediation_plan.json"
AUDIT_FILE = REPORT_DIR / "audit_log.jsonl"

TEST_CERTIFICATE = "remediation-test.crt"
TEST_CERTIFICATE_PATH = (
    "sandbox/certificates/remediation-tests/remediation-test.crt"
)

VALID_SCOPES = [
    "TEST_ONLY",
    "DRY_RUN_ONLY",
    "REVOKE_AND_REISSUE"
]


def load_plan():
    if not PLAN_FILE.exists():
        raise FileNotFoundError("Remediation plan not found.")

    with open(PLAN_FILE, "r") as file:
        return json.load(file)


def save_plan(plan):
    backup = PLAN_FILE.with_suffix(".json.bak")

    if PLAN_FILE.exists():
        backup.write_bytes(PLAN_FILE.read_bytes())

    temporary = PLAN_FILE.with_suffix(".json.tmp")

    with open(temporary, "w") as file:
        json.dump(plan, file, indent=4)
        file.flush()
        os.fsync(file.fileno())

    temporary.replace(PLAN_FILE)


def write_audit_record(record):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with open(AUDIT_FILE, "a") as file:
        file.write(json.dumps(record) + "\n")
        file.flush()
        os.fsync(file.fileno())


def validate_certificate_path(item):
    certificate_path = (PROJECT_ROOT / item["path"]).resolve()

    if not certificate_path.is_relative_to(CERT_DIR):
        raise ValueError("Certificate path is outside the sandbox.")

    if not certificate_path.is_file():
        raise FileNotFoundError("Certificate file does not exist.")

    return certificate_path


def validate_destructive_scope(item):
    expected_path = (
        PROJECT_ROOT / TEST_CERTIFICATE_PATH
    ).resolve()

    actual_path = (
        PROJECT_ROOT / item["path"]
    ).resolve()

    if item.get("certificate") != TEST_CERTIFICATE:
        raise ValueError(
            "REVOKE_AND_REISSUE is restricted to the dedicated test certificate."
        )

    if actual_path != expected_path:
        raise ValueError(
            "Certificate path does not match the dedicated test fixture."
        )

    if item.get("test_fixture") is not True:
        raise ValueError(
            "Certificate is not marked as an authorized test fixture."
        )

    if not item.get("ca_issued") or not item.get("revocation_eligible"):
        raise ValueError(
            "Test certificate must be locally CA-issued and revocation-eligible."
        )


def list_pending(plan):
    print("\n========== PENDING APPROVALS ==========\n")

    pending = [
        item for item in plan.get("remediation_items", [])
        if item.get("approval_status") == "PENDING"
    ]

    if not pending:
        print("No pending approvals.")
        return

    for index, item in enumerate(pending, start=1):
        print(f"{index}. {item['certificate']}")
        print(f"   Severity: {item['severity']}")
        print(f"   Issues: {item['total_issues']}")
        print(f"   CA-issued: {item['ca_issued']}")
        print(f"   Revocation eligible: {item['revocation_eligible']}")
        print(f"   Test fixture: {item.get('test_fixture', False)}")
        print("   Approval: PENDING\n")

    print("Total pending:", len(pending))


def record_decision(certificate, decision, scope, reason):
    plan = load_plan()

    matches = [
        item for item in plan.get("remediation_items", [])
        if item.get("certificate") == certificate
    ]

    if len(matches) != 1:
        raise ValueError(
            "Certificate not found or certificate name is ambiguous."
        )

    item = matches[0]

    if item.get("approval_status") != "PENDING":
        raise ValueError(
            "This certificate already has an approval decision."
        )

    validate_certificate_path(item)

    if decision == "APPROVED":
        if scope not in VALID_SCOPES:
            raise ValueError("Invalid approval scope.")

        if scope in ["DRY_RUN_ONLY", "REVOKE_AND_REISSUE"]:
            if not item.get("ca_issued") or not item.get("revocation_eligible"):
                raise ValueError(
                    "This approval scope requires a locally CA-issued certificate."
                )

        if scope == "REVOKE_AND_REISSUE":
            validate_destructive_scope(item)

    else:
        scope = "NONE"

    timestamp = datetime.now(timezone.utc).isoformat()

    audit_record = {
        "timestamp": timestamp,
        "event": "REMEDIATION_APPROVAL_DECISION",
        "certificate": certificate,
        "serial_number": item.get("serial_number"),
        "decision": decision,
        "approval_scope": scope,
        "reason": reason,
        "actor": "local_operator",
        "ca_issued": item.get("ca_issued"),
        "revocation_eligible": item.get("revocation_eligible"),
        "test_fixture": item.get("test_fixture", False),
        "execution_performed": False
    }

    item["approval_status"] = decision
    item["approval_decision"] = decision
    item["approval_scope"] = scope
    item["approval_timestamp"] = timestamp
    item["approval_reason"] = reason
    item["approved_by"] = "local_operator"

    save_plan(plan)
    write_audit_record(audit_record)

    print("\n========== APPROVAL RESULT ==========\n")
    print("Certificate:", certificate)
    print("Decision:", decision)
    print("Approval scope:", scope)
    print("Reason:", reason)
    print("Execution performed: NO")
    print("\n[SECURITY] No certificate was modified or revoked.")
    print("Audit log:", AUDIT_FILE)


def main():
    parser = argparse.ArgumentParser(
        description="PKI Human Approval Workflow"
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List pending approval requests"
    )

    parser.add_argument(
        "--certificate",
        help="Exact certificate filename"
    )

    parser.add_argument(
        "--decision",
        choices=["approve", "reject"],
        help="Approval decision"
    )

    parser.add_argument(
        "--scope",
        choices=VALID_SCOPES,
        help="Scope of an approval decision"
    )

    parser.add_argument(
        "--reason",
        help="Reason for the decision"
    )

    args = parser.parse_args()

    try:
        if args.list:
            if any([
                args.certificate,
                args.decision,
                args.scope,
                args.reason
            ]):
                parser.error(
                    "--list cannot be combined with decision arguments."
                )

            list_pending(load_plan())
            return

        if not all([
            args.certificate,
            args.decision,
            args.reason
        ]):
            parser.error(
                "Provide --certificate, --decision and --reason."
            )

        if not args.reason.strip():
            parser.error("Reason cannot be empty.")

        if args.decision == "approve" and not args.scope:
            parser.error("Approval requires --scope.")

        if args.decision == "reject" and args.scope:
            parser.error("Do not provide --scope when rejecting.")

        decision = (
            "APPROVED"
            if args.decision == "approve"
            else "REJECTED"
        )

        record_decision(
            args.certificate,
            decision,
            args.scope,
            args.reason.strip()
        )

    except (FileNotFoundError, ValueError, OSError, KeyError) as error:
        print("\n[ERROR]", error)


if __name__ == "__main__":
    main()
