
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtensionOID

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CERT_DIR = (
    PROJECT_ROOT / "sandbox" / "certificates"
).resolve()

PLAN_FILE = (
    PROJECT_ROOT
    / "agents"
    / "responder"
    / "reports"
    / "remediation_plan.json"
)

AUDIT_LOG = (
    PROJECT_ROOT
    / "agents"
    / "responder"
    / "reports"
    / "audit_log.jsonl"
)

ROOT_CA_FILE = PROJECT_ROOT / "sandbox" / "ca" / "certs" / "root_ca.crt"
INTERMEDIATE_CA_FILE = PROJECT_ROOT / "sandbox" / "ca" / "certs" / "intermediate_ca.crt"


def load_certificate(path):
    if not path.is_file():
        raise FileNotFoundError(f"Certificate file missing: {path}")

    with open(path, "rb") as file:
        return x509.load_pem_x509_certificate(file.read())


def load_plan():
    if not PLAN_FILE.is_file():
        raise FileNotFoundError("Remediation plan not found.")

    with open(PLAN_FILE, "r") as file:
        return json.load(file)


def find_certificate(plan, filename):
    matches = [
        item for item in plan.get("remediation_items", [])
        if item.get("certificate") == filename
    ]

    if len(matches) != 1:
        raise ValueError(
            "Certificate not found or certificate name is ambiguous."
        )

    return matches[0]


def validate_path(item):
    relative_path = Path(item["path"])

    if relative_path.is_absolute():
        raise ValueError("Absolute certificate paths are not permitted.")

    path = (PROJECT_ROOT / relative_path).resolve()

    if not path.is_relative_to(CERT_DIR):
        raise ValueError("Certificate is outside the sandbox.")

    if not path.is_file():
        raise FileNotFoundError("Certificate file does not exist.")

    return path


def validate_ca_certificate(ca_cert, name):
    try:
        constraints = ca_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        raise ValueError(f"{name} has no Basic Constraints extension.")

    if not constraints.ca:
        raise ValueError(f"{name} is not marked as a CA certificate.")


def verify_certificate_chain(cert):
    root_cert = load_certificate(ROOT_CA_FILE)
    intermediate_cert = load_certificate(INTERMEDIATE_CA_FILE)

    validate_ca_certificate(root_cert, "Root CA")
    validate_ca_certificate(intermediate_cert, "Intermediate CA")

    if intermediate_cert.issuer != root_cert.subject:
        raise ValueError("Intermediate CA issuer does not match Root CA.")

    if cert.issuer != intermediate_cert.subject:
        raise ValueError("Certificate issuer does not match Intermediate CA.")

    try:
        intermediate_cert.verify_directly_issued_by(root_cert)
        cert.verify_directly_issued_by(intermediate_cert)

    except InvalidSignature:
        raise ValueError("Certificate-chain signature verification failed.")

    except Exception as error:
        raise ValueError(
            f"Certificate-chain verification failed: {error}"
        )

    return root_cert, intermediate_cert


def validate_certificate(item, certificate_path):
    cert = load_certificate(certificate_path)

    actual_serial = format(cert.serial_number, "X")

    if actual_serial.upper() != item["serial_number"].upper():
        raise ValueError("Certificate serial number does not match the plan.")

    verify_certificate_chain(cert)

    return cert


def check_approval(item):
    if item.get("approval_status") != "APPROVED":
        raise ValueError("Certificate does not have an approved decision.")

    if item.get("approval_decision") != "APPROVED":
        raise ValueError("Approval decision is invalid.")

    if item.get("approval_scope") != "DRY_RUN_ONLY":
        raise ValueError(
            "Executor requires explicit DRY_RUN_ONLY approval."
        )

    if not item.get("approval_reason"):
        raise ValueError("Approval reason is missing.")

    if not item.get("approved_by"):
        raise ValueError("Approver information is missing.")

    if not item.get("ca_issued") or not item.get("revocation_eligible"):
        raise ValueError("Certificate is not eligible for local CA remediation.")

    if item.get("remediation_status") != "NOT_STARTED":
        raise ValueError("Remediation has already started or changed status.")


def get_certificate_status(cert):
    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc:
        return "NOT_YET_VALID"

    if now >= cert.not_valid_after_utc:
        return "EXPIRED"

    return "VALID"


def get_proposed_action(status):
    if status == "EXPIRED":
        return "REPLACEMENT_RECOMMENDED"

    if status == "NOT_YET_VALID":
        return "INVESTIGATE_VALIDITY_CONFIGURATION"

    return "REVIEW_REVOCATION_AND_REPLACEMENT_REQUIREMENTS"


def write_audit_event(item, cert, status, proposed_action):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "REMEDIATION_DRY_RUN_COMPLETED",
        "certificate": item["certificate"],
        "serial_number": item["serial_number"],
        "approval_scope": item["approval_scope"],
        "approver": item["approved_by"],
        "certificate_status": status,
        "chain_verification": "PASSED",
        "proposed_action": proposed_action,
        "execution_performed": False,
        "certificate_modified": False,
        "certificate_revoked": False,
        "replacement_issued": False,
        "deployment_performed": False
    }

    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    with open(AUDIT_LOG, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
        file.flush()

    return event


def preview_remediation(item, cert):
    now = datetime.now(timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    status = get_certificate_status(cert)
    proposed_action = get_proposed_action(status)

    print("\n========== REMEDIATION DRY RUN ==========\n")

    print("Certificate:", item["certificate"])
    print("Serial number:", item["serial_number"])
    print("Severity:", item["severity"])

    print("\n========== APPROVAL VALIDATION ==========")
    print("Decision:", item["approval_status"])
    print("Scope:", item["approval_scope"])
    print("Approver:", item["approved_by"])
    print("Approval validation: PASSED")

    print("\n========== CERTIFICATE VALIDATION ==========")
    print("Serial validation: PASSED")
    print("Sandbox path validation: PASSED")
    print("Root CA validation: PASSED")
    print("Intermediate CA validation: PASSED")
    print("Certificate signature verification: PASSED")
    print("Certificate-chain verification: PASSED")

    print("\n========== CERTIFICATE STATUS ==========")
    print("Not before:", not_before.isoformat())
    print("Not after:", not_after.isoformat())
    print("Status:", status)

    if status == "VALID":
        print("Remaining lifetime:", not_after - now)

    print("\n========== PROPOSED REMEDIATION ==========")

    if status == "EXPIRED":
        print("Certificate has expired.")
        print("Proposed action: Issue a replacement certificate.")
        print("Revocation: Not required for an already expired certificate.")

    elif status == "NOT_YET_VALID":
        print("Certificate is not yet valid.")
        print("Proposed action: Investigate validity configuration.")

    else:
        print("Certificate is currently valid.")
        print("Proposed action: Review revocation and replacement requirements.")

    print("\n========== EXECUTION STATUS ==========")
    print("Execution performed: NO")
    print("Certificate modified: NO")
    print("Certificate revoked: NO")
    print("Replacement issued: NO")
    print("Deployment performed: NO")

    event = write_audit_event(
        item,
        cert,
        status,
        proposed_action
    )

    print("\n========== AUDIT RESULT ==========")
    print("Event:", event["event"])
    print("Audit log:", AUDIT_LOG)
    print("Audit event recorded: YES")

    print("\n[SAFE MODE] Validation and preview completed only.")


def main():
    parser = argparse.ArgumentParser(
        description="PKI Remediation Executor - Dry Run Only"
    )

    parser.add_argument(
        "--certificate",
        required=True,
        help="Exact certificate filename"
    )

    args = parser.parse_args()

    try:
        plan = load_plan()
        item = find_certificate(plan, args.certificate)

        check_approval(item)

        certificate_path = validate_path(item)
        cert = validate_certificate(item, certificate_path)

        preview_remediation(item, cert)

    except (
        FileNotFoundError,
        ValueError,
        KeyError,
        OSError
    ) as error:
        print("\n[EXECUTION BLOCKED]", error)


if __name__ == "__main__":
    main()
