
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TEST_CERTIFICATE = "remediation-test.crt"
EXPECTED_SERIAL = "9A440E33171D3485A89438C0965B7915"
EXPECTED_SUBJECT = "remediation-test.pki.local"

TEST_DIR = PROJECT_ROOT / "sandbox/certificates/remediation-tests"
ORIGINAL_CERT = TEST_DIR / TEST_CERTIFICATE
ORIGINAL_KEY = TEST_DIR / "remediation-test.key"

REPLACEMENT_CERT = TEST_DIR / "remediation-replacement.crt"
REPLACEMENT_KEY = TEST_DIR / "remediation-replacement.key"

DEPLOYMENT_DIR = PROJECT_ROOT / "sandbox/deployments/remediation-test"

PLAN_FILE = PROJECT_ROOT / "agents/responder/reports/remediation_plan.json"
AUDIT_LOG = PROJECT_ROOT / "agents/responder/reports/audit_log.jsonl"
NOTIFICATION_LOG = (
    PROJECT_ROOT / "agents/responder/reports/operator_notifications.jsonl"
)
STATE_FILE = (
    PROJECT_ROOT / "agents/responder/reports/remediation_execution_state.json"
)

CA_CONTAINER = "pki-local-ca"
CA_URL = "https://localhost:9000"
CA_ROOT = "/home/step/certs/root_ca.crt"
CA_PASSWORD = "/home/step/secrets/password"
CONTAINER_CERT_DIR = "/certificates/remediation-tests"

VALID_STAGES = {
    "NOT_STARTED",
    "REVOCATION_IN_PROGRESS",
    "REVOCATION_EVIDENCE_PENDING",
    "REVOCATION_VERIFICATION_FAILED",
    "REVOKED",
    "REPLACEMENT_ISSUED",
    "VERIFIED",
    "DEPLOYED",
    "COMPLETED",
}

COMPLETED_OPERATION_STAGES = {
    "REVOKED",
    "REPLACEMENT_ISSUED",
    "VERIFIED",
    "DEPLOYED",
    "COMPLETED",
}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def audit(event, **details):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": timestamp(),
        "event": event,
        "certificate": TEST_CERTIFICATE,
        "serial_number": EXPECTED_SERIAL,
        "environment": "local-sandbox",
        **details,
    }

    with AUDIT_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def latest_accepted_revocation_event():
    """Return the latest successful revoke event for this test certificate."""
    if not AUDIT_LOG.is_file():
        return None

    records = []
    for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    matching = [
        record for record in records
        if record.get("certificate") == TEST_CERTIFICATE
        and record.get("serial_number") == EXPECTED_SERIAL
        and record.get("environment") == "local-sandbox"
    ]

    latest_start = max(
        (
            index for index, record in enumerate(matching)
            if record.get("event") == "REVOCATION_REQUEST_STARTED"
        ),
        default=-1,
    )

    for record in reversed(matching[latest_start + 1:]):
        if record.get("event") == "REVOCATION_REQUEST_ACCEPTED":
            return record

    return None


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip()
        command_text = subprocess.list2cmdline(command)
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}. "
            f"Command: {command_text}. Output: {error[-1500:]}"
        )

    output = [result.stdout.strip(), result.stderr.strip()]
    return "\n".join(part for part in output if part)


def load_certificate(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def serial_hex(cert):
    return format(cert.serial_number, "X").upper()


def public_key_bytes(key):
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_approved_item():
    if not PLAN_FILE.exists():
        raise RuntimeError("Remediation plan does not exist.")

    plan = json.loads(PLAN_FILE.read_text(encoding="utf-8"))

    matches = [
        item for item in plan.get("remediation_items", [])
        if item.get("certificate") == TEST_CERTIFICATE
    ]

    if len(matches) != 1:
        raise RuntimeError(
            "Expected exactly one dedicated remediation test entry."
        )

    item = matches[0]

    required_checks = {
        "test_fixture": True,
        "approval_status": "APPROVED",
        "approval_decision": "APPROVED",
        "approval_scope": "REVOKE_AND_REISSUE",
        "ca_issued": True,
        "revocation_eligible": True,
    }

    for field, expected in required_checks.items():
        if item.get(field) != expected:
            raise RuntimeError(
                f"Approval validation failed for field: {field}"
            )

    expected_path = (
        "sandbox/certificates/remediation-tests/remediation-test.crt"
    )

    if item.get("path") != expected_path:
        raise RuntimeError("Unexpected certificate path.")

    if not item.get("approved_by") or not item.get("approval_reason"):
        raise RuntimeError("Approval record is incomplete.")

    if item.get("serial_number") != EXPECTED_SERIAL:
        raise RuntimeError("Certificate serial mismatch in approval record.")

    return item


def update_plan_status(status):
    plan = json.loads(PLAN_FILE.read_text(encoding="utf-8"))

    matches = [
        item for item in plan.get("remediation_items", [])
        if item.get("certificate") == TEST_CERTIFICATE
    ]

    if len(matches) != 1:
        raise RuntimeError("Cannot uniquely identify test certificate.")

    matches[0]["remediation_status"] = status

    temporary = PLAN_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(plan, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, PLAN_FILE)


def load_state():
    if not STATE_FILE.exists():
        return {"stage": "NOT_STARTED"}

    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))

    if state.get("stage") not in VALID_STAGES:
        raise RuntimeError("Invalid execution state. Manual review required.")

    if state.get("serial_number") != EXPECTED_SERIAL:
        raise RuntimeError("Execution state serial mismatch.")

    return state


def save_state(stage, **details):
    state = {
        "stage": stage,
        "serial_number": EXPECTED_SERIAL,
        "certificate": TEST_CERTIFICATE,
        "updated_at": timestamp(),
        **details,
    }

    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(state, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, STATE_FILE)
    update_plan_status(stage)


def validate_original_certificate():
    if not ORIGINAL_CERT.is_file() or not ORIGINAL_KEY.is_file():
        raise RuntimeError("Original certificate or private key is missing.")

    cert = load_certificate(ORIGINAL_CERT)

    if serial_hex(cert) != EXPECTED_SERIAL:
        raise RuntimeError("Original certificate serial mismatch.")

    common_names = cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )

    if not common_names or common_names[0].value != EXPECTED_SUBJECT:
        raise RuntimeError("Original certificate subject mismatch.")

    private_key = serialization.load_pem_private_key(
        ORIGINAL_KEY.read_bytes(),
        password=None,
    )

    if public_key_bytes(private_key.public_key()) != public_key_bytes(
        cert.public_key()
    ):
        raise RuntimeError("Original certificate and key do not match.")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise RuntimeError("Expected an RSA private key.")

    if private_key.key_size < 2048:
        raise RuntimeError("Original key is weaker than RSA-2048.")

    run_command([
        "docker", "exec", CA_CONTAINER,
        "step", "certificate", "verify",
        f"{CONTAINER_CERT_DIR}/{TEST_CERTIFICATE}",
        "--roots", CA_ROOT,
    ])

    return cert


def revoke_original_certificate(cert):
    if serial_hex(cert) != EXPECTED_SERIAL:
        raise RuntimeError("Refusing to revoke an unexpected certificate.")

    audit("REVOCATION_REQUEST_STARTED", authorization_method="mTLS")

    # Use the documented mTLS route. Passing both --cert and --key means
    # Step CLI should infer the serial from the certificate and must not
    # try to generate a provisioner token.
    response = run_command([
        "docker", "exec", CA_CONTAINER,
        "step", "ca", "revoke",
        "--cert", f"{CONTAINER_CERT_DIR}/{TEST_CERTIFICATE}",
        "--key", f"{CONTAINER_CERT_DIR}/remediation-test.key",
        "--reason", "Certificate superseded by replacement",
        "--reasonCode", "4",
        "--ca-url", CA_URL,
        "--root", CA_ROOT,
    ])

    audit(
        "REVOCATION_REQUEST_ACCEPTED",
        authorization_method="mTLS",
        ca_response=response[-500:],
        ca_operation_attempted=True,
    )


def verify_revocation():
    """
    Probe renewal using the original certificate and key.

    A successful renewal means revocation is not confirmed.
    Only an explicit CA revocation response can become reviewable evidence.
    All other failures block the workflow.
    """

    health = run_command([
        "docker", "exec", CA_CONTAINER,
        "step", "ca", "health",
        "--ca-url", CA_URL,
        "--root", CA_ROOT,
    ])

    probe_name = f"revocation-probe-{uuid.uuid4().hex}.crt"
    container_probe = f"/tmp/{probe_name}"

    command = [
        "docker", "exec", CA_CONTAINER,
        "step", "ca", "renew",
        f"{CONTAINER_CERT_DIR}/{TEST_CERTIFICATE}",
        f"{CONTAINER_CERT_DIR}/remediation-test.key",
        "--out", container_probe,
        "--ca-url", CA_URL,
        "--root", CA_ROOT,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    output = (result.stdout + "\\n" + result.stderr).strip()

    try:
        evidence_hash = hashlib.sha256(
            output.encode("utf-8")
        ).hexdigest()

        if result.returncode == 0:
            save_state(
                "NOT_STARTED",
                revocation_verified=False,
                verification_method="mTLS renewal probe",
                probe_return_code=0,
                ca_response="Renewal succeeded; revocation not confirmed.",
                evidence_sha256=evidence_hash,
                ca_health_response=health[-500:],
                verification_timestamp=timestamp(),
            )

            audit(
                "REVOCATION_NOT_CONFIRMED",
                reason="Original certificate successfully renewed.",
                evidence_sha256=evidence_hash,
                replacement_issued=False,
            )

            print("\\n[NOT REVOKED] The CA successfully renewed the original certificate.")
            print("The temporary renewal certificate will be deleted.")
            print("State safely returned to NOT_STARTED.")
            print("A new revocation attempt may be considered.")
            return

        lowered = output.lower()
        explicit_revocation = (
            "certificate has been revoked" in lowered
            or "certificate is revoked" in lowered
        )

        if explicit_revocation:
            save_state(
                "REVOCATION_EVIDENCE_PENDING",
                revocation_verified=False,
                verification_method="explicit CA revocation response",
                probe_return_code=result.returncode,
                ca_response=output[-2000:],
                evidence_sha256=evidence_hash,
                ca_health_response=health[-500:],
                evidence_recorded_at=timestamp(),
            )

            audit(
                "REVOCATION_EVIDENCE_PENDING_MANUAL_REVIEW",
                probe_return_code=result.returncode,
                evidence_sha256=evidence_hash,
                ca_response=output[-1000:],
                revocation_verified=False,
                replacement_issued=False,
            )

            print("\\n[REVIEW REQUIRED] CA explicitly reported revocation.")
            print(output[-2000:])
            print(f"Evidence SHA-256: {evidence_hash}")
            print("State: REVOCATION_EVIDENCE_PENDING")
            print("No replacement has been issued.")
            return

        accepted_event = latest_accepted_revocation_event()
        generic_authorization_denial = (
            "request lacked necessary authorization" in lowered
        )

        if accepted_event and generic_authorization_denial:
            evidence_payload = {
                "accepted_revocation_event": accepted_event,
                "renewal_probe_output": output[-2000:],
            }
            evidence_hash = hashlib.sha256(
                json.dumps(
                    evidence_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()

            save_state(
                "REVOCATION_EVIDENCE_PENDING",
                revocation_verified=False,
                verification_method=(
                    "successful revoke command plus renewal authorization "
                    "denial; operator review required"
                ),
                revocation_request_accepted=True,
                revocation_acceptance_timestamp=accepted_event["timestamp"],
                revocation_acceptance_response=(
                    accepted_event.get("ca_response", "")
                ),
                probe_return_code=result.returncode,
                ca_response=output[-2000:],
                evidence_sha256=evidence_hash,
                ca_health_response=health[-500:],
                evidence_recorded_at=timestamp(),
            )

            audit(
                "REVOCATION_EVIDENCE_PENDING_MANUAL_REVIEW",
                probe_return_code=result.returncode,
                evidence_sha256=evidence_hash,
                accepted_revocation_event=accepted_event["timestamp"],
                ca_response=output[-1000:],
                revocation_verified=False,
                replacement_issued=False,
            )

            print(
                "\n[REVIEW REQUIRED] The revoke command succeeded, and "
                "the renewal probe was denied authorization."
            )
            print("Review the accepted revocation audit entry and CA logs.")
            print(f"Evidence SHA-256: {evidence_hash}")
            print("No replacement has been issued.")
            return

        save_state(
            "REVOCATION_VERIFICATION_FAILED",
            revocation_verified=False,
            verification_method="mTLS renewal probe",
            probe_return_code=result.returncode,
            ca_response=output[-2000:] or "No CA response returned.",
            evidence_sha256=evidence_hash,
            ca_health_response=health[-500:],
            verification_timestamp=timestamp(),
        )

        audit(
            "REVOCATION_VERIFICATION_BLOCKED",
            probe_return_code=result.returncode,
            evidence_sha256=evidence_hash,
            ca_response=output[-1000:],
            replacement_issued=False,
        )

        print("\\n[BLOCKED] Renewal failed without explicit revocation evidence.")
        print(output[-2000:] or "No CA response returned.")
        print("Manual investigation is required.")
        print("No replacement has been issued.")

    finally:
        subprocess.run(
            [
                "docker", "exec", CA_CONTAINER,
                "rm", "-f", container_probe,
            ],
            capture_output=True,
            text=True,
            check=False,
        )


def confirm_revocation_after_review(evidence_sha256):
    state = load_state()

    if state["stage"] != "REVOCATION_EVIDENCE_PENDING":
        raise RuntimeError(
            "Manual confirmation requires REVOCATION_EVIDENCE_PENDING."
        )

    response = (state.get("ca_response") or "").lower()

    explicit_revocation = (
        "certificate has been revoked" in response
        or "certificate is revoked" in response
    )
    correlated_revocation_evidence = (
        state.get("revocation_request_accepted") is True
        and state.get("probe_return_code") not in (None, 0)
        and "request lacked necessary authorization" in response
    )

    if not (explicit_revocation or correlated_revocation_evidence):
        raise RuntimeError(
            "Stored evidence does not support manual revocation confirmation."
        )

    stored_hash = state.get("evidence_sha256")

    if not stored_hash or evidence_sha256 != stored_hash:
        raise RuntimeError(
            "Evidence SHA-256 mismatch. Confirmation rejected."
        )

    save_state(
        "REVOKED",
        revocation_verified=True,
        verification_method=(
            "operator reviewed revocation evidence and confirmed"
        ),
        evidence_sha256=stored_hash,
        operator_confirmed_revocation=True,
        operator_confirmation_timestamp=timestamp(),
    )

    audit(
        "REVOCATION_MANUALLY_CONFIRMED",
        evidence_sha256=stored_hash,
        operator_confirmed=True,
        replacement_issued=False,
    )

    print("\\n[CONFIRMED] Operator accepted the exact stored CA evidence.")
    print("[PAUSED] Replacement issuance has NOT started.")
    print("Inspect the state and audit log before the next operation.")


def issue_replacement():
    if REPLACEMENT_CERT.exists() or REPLACEMENT_KEY.exists():
        raise RuntimeError(
            "Replacement files already exist. Manual review required."
        )

    container_cert = (
        f"{CONTAINER_CERT_DIR}/remediation-replacement.crt"
    )
    container_key = (
        f"{CONTAINER_CERT_DIR}/remediation-replacement.key"
    )

    command = (
        "umask 077 && exec step ca certificate "
        f"{EXPECTED_SUBJECT} {container_cert} {container_key} "
        f"--san={EXPECTED_SUBJECT} "
        "--not-after=192h "
        "--kty=RSA "
        "--size=2048 "
        "--provisioner=admin@pki.local "
        f"--provisioner-password-file={CA_PASSWORD} "
        f"--ca-url={CA_URL} "
        f"--root={CA_ROOT}"
    )

    run_command([
        "docker", "exec", CA_CONTAINER,
        "sh", "-c", command,
    ])

    if not REPLACEMENT_CERT.is_file() or not REPLACEMENT_KEY.is_file():
        raise RuntimeError("CA did not create both replacement files.")

    os.chmod(REPLACEMENT_KEY, 0o600)

    audit(
        "REPLACEMENT_CERTIFICATE_ISSUED",
        execution_performed=True,
    )


def verify_replacement(original):
    if not REPLACEMENT_CERT.is_file() or not REPLACEMENT_KEY.is_file():
        raise RuntimeError("Replacement certificate or key is missing.")

    replacement = load_certificate(REPLACEMENT_CERT)

    if serial_hex(replacement) == EXPECTED_SERIAL:
        raise RuntimeError("Replacement serial matches original.")

    if replacement.subject != original.subject:
        raise RuntimeError("Replacement subject mismatch.")

    if replacement.issuer != original.issuer:
        raise RuntimeError("Replacement issuer mismatch.")

    now = datetime.now(timezone.utc)

    not_before = replacement.not_valid_before.replace(
        tzinfo=timezone.utc
    )
    not_after = replacement.not_valid_after.replace(
        tzinfo=timezone.utc
    )

    if not_before > now or not_after <= now:
        raise RuntimeError("Replacement certificate is not currently valid.")

    private_key = serialization.load_pem_private_key(
        REPLACEMENT_KEY.read_bytes(),
        password=None,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise RuntimeError("Replacement key is not RSA.")

    if private_key.key_size < 2048:
        raise RuntimeError("Replacement key is weaker than RSA-2048.")

    if public_key_bytes(private_key.public_key()) != public_key_bytes(
        replacement.public_key()
    ):
        raise RuntimeError("Replacement certificate and key mismatch.")

    try:
        san = replacement.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        raise RuntimeError("Replacement SAN extension is missing.")

    if EXPECTED_SUBJECT not in san.get_values_for_type(x509.DNSName):
        raise RuntimeError("Expected hostname is missing from replacement SAN.")

    run_command([
        "docker", "exec", CA_CONTAINER,
        "step", "certificate", "verify",
        f"{CONTAINER_CERT_DIR}/remediation-replacement.crt",
        "--roots", CA_ROOT,
    ])

    audit(
        "REPLACEMENT_CERTIFICATE_VERIFIED",
        replacement_serial=serial_hex(replacement),
        key_size=private_key.key_size,
        chain_verified=True,
    )


def deploy_replacement():
    if not REPLACEMENT_CERT.is_file() or not REPLACEMENT_KEY.is_file():
        raise RuntimeError("Cannot deploy missing replacement files.")

    if DEPLOYMENT_DIR.exists():
        deployed_cert = DEPLOYMENT_DIR / "remediation-replacement.crt"
        deployed_key = DEPLOYMENT_DIR / "remediation-replacement.key"

        if not deployed_cert.is_file() or not deployed_key.is_file():
            raise RuntimeError("Existing deployment is incomplete.")

        if deployed_cert.read_bytes() != REPLACEMENT_CERT.read_bytes():
            raise RuntimeError("Deployed certificate does not match.")

        if deployed_key.read_bytes() != REPLACEMENT_KEY.read_bytes():
            raise RuntimeError("Deployed key does not match.")

        os.chmod(deployed_key, 0o600)
        return

    DEPLOYMENT_DIR.parent.mkdir(parents=True, exist_ok=True)

    staging_dir = Path(
        tempfile.mkdtemp(
            dir=DEPLOYMENT_DIR.parent,
            prefix="remediation-deploy-",
        )
    )

    try:
        shutil.copy2(
            REPLACEMENT_CERT,
            staging_dir / "remediation-replacement.crt",
        )

        shutil.copy2(
            REPLACEMENT_KEY,
            staging_dir / "remediation-replacement.key",
        )

        os.chmod(
            staging_dir / "remediation-replacement.key",
            0o600,
        )

        os.replace(staging_dir, DEPLOYMENT_DIR)

    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)

    audit(
        "SANDBOX_DEPLOYMENT_SIMULATED",
        deployment_path=str(DEPLOYMENT_DIR.relative_to(PROJECT_ROOT)),
    )


def notify_operator():
    NOTIFICATION_LOG.parent.mkdir(parents=True, exist_ok=True)

    if NOTIFICATION_LOG.exists():
        for line in NOTIFICATION_LOG.read_text(
            encoding="utf-8"
        ).splitlines():

            if not line.strip():
                continue

            record = json.loads(line)

            if (
                record.get("event") == "REMEDIATION_COMPLETED"
                and record.get("serial_number") == EXPECTED_SERIAL
            ):
                return

    notification = {
        "timestamp": timestamp(),
        "event": "REMEDIATION_COMPLETED",
        "certificate": TEST_CERTIFICATE,
        "serial_number": EXPECTED_SERIAL,
        "message": (
            "Sandbox certificate remediation completed. "
            "Replacement issued, verified and deployed in simulation."
        ),
        "notification_type": "LOCAL_AUDIT_NOTIFICATION",
    }

    with NOTIFICATION_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(notification) + "\n")

    audit("OPERATOR_NOTIFICATION_RECORDED")


def execute_workflow(
    verify_revocation_requested=False,
    confirm_revoked_requested=False,
    evidence_sha256=None,
):
    item = load_approved_item()
    state = load_state()
    stage = state["stage"]

    if stage == "COMPLETED":
        raise RuntimeError("Remediation has already completed.")

    if verify_revocation_requested:
        if stage not in {
            "REVOCATION_IN_PROGRESS",
            "REVOCATION_VERIFICATION_FAILED",
        }:
            raise RuntimeError(
                "Verification is only valid while revocation is in progress "
                "or blocked pending verification."
            )

        print("[CHECK] Running independent renewal probe...")
        verify_revocation()
        return

    if confirm_revoked_requested:
        confirm_revocation_after_review(evidence_sha256)
        return

    if stage == "REVOCATION_IN_PROGRESS":
        raise RuntimeError(
            "Revocation outcome is uncertain. Run the verification step."
        )

    if stage == "REVOCATION_EVIDENCE_PENDING":
        raise RuntimeError(
            "Revocation evidence requires manual inspection and "
            "explicit confirmation. No replacement can be issued yet."
        )

    if stage == "REVOCATION_VERIFICATION_FAILED":
        raise RuntimeError(
            "Revocation verification failed. Workflow is blocked pending "
            "manual investigation. No replacement can be issued."
        )

    print("\n========== CONTROLLED PKI REMEDIATION ==========")
    print(f"Certificate: {TEST_CERTIFICATE}")
    print(f"Serial:      {EXPECTED_SERIAL}")
    print(f"Approval:    {item['approval_status']}")
    print(f"Stage:       {stage}")
    print("Environment: LOCAL SANDBOX ONLY")
    print("")

    original = validate_original_certificate()

    if stage == "NOT_STARTED":
        if REPLACEMENT_CERT.exists() or REPLACEMENT_KEY.exists():
            raise RuntimeError("Unexpected replacement artifacts exist.")

        if DEPLOYMENT_DIR.exists():
            raise RuntimeError("Unexpected deployment directory exists.")

        save_state("REVOCATION_IN_PROGRESS")
        audit("REMEDIATION_EXECUTION_STARTED")

        revoke_original_certificate(original)

        print("\n[PAUSED] CA accepted the revocation request.")
        print("[SAFETY] Independent verification is required.")
        print("[SAFETY] Replacement issuance has NOT started.")
        return

    if stage == "REVOKED":
        if state.get("revocation_verified") is not True:
            raise RuntimeError("Revocation verification evidence is missing.")

        if state.get("operator_confirmed_revocation") is not True:
            raise RuntimeError("Operator confirmation is missing.")

        issue_replacement()
        save_state("REPLACEMENT_ISSUED")
        stage = "REPLACEMENT_ISSUED"

    if stage == "REPLACEMENT_ISSUED":
        verify_replacement(original)
        save_state("VERIFIED")
        stage = "VERIFIED"

    if stage == "VERIFIED":
        deploy_replacement()
        save_state("DEPLOYED")
        stage = "DEPLOYED"

    if stage == "DEPLOYED":
        notify_operator()
        save_state("COMPLETED")
        audit("REMEDIATION_WORKFLOW_COMPLETED")

    print("\n[SUCCESS] Remediation workflow completed.")
    print(f"Final stage: {load_state()['stage']}")
    print("Deployment is a local sandbox simulation.")
    print("Smallstep passive revocation does not actively invalidate")
    print("an already-issued certificate for every relying party.")


def main():
    parser = argparse.ArgumentParser(
        description="Controlled PKI sandbox remediation executor"
    )

    parser.add_argument(
        "--certificate",
        required=True,
        help="Must be remediation-test.crt",
    )

    parser.add_argument(
        "--environment",
        choices=["local-sandbox"],
        default="local-sandbox",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Explicitly authorize the controlled sandbox operation",
    )

    parser.add_argument(
        "--verify-revocation",
        action="store_true",
        help="Run a renewal probe and save its response for manual review",
    )

    parser.add_argument(
        "--confirm-revoked",
        action="store_true",
        help="Record operator confirmation after manually reviewing CA evidence",
    )

    parser.add_argument(
        "--confirm-serial",
        help="Must exactly match the approved certificate serial",
    )

    parser.add_argument(
        "--evidence-sha256",
        help="Exact SHA-256 hash printed by the revocation evidence review",
    )

    args = parser.parse_args()

    if args.certificate != TEST_CERTIFICATE:
        parser.error("Only remediation-test.crt is permitted.")

    if not args.execute:
        parser.error("Execution flag missing. No changes performed.")

    if args.confirm_serial != EXPECTED_SERIAL:
        parser.error("Exact certificate serial confirmation is required.")

    if args.verify_revocation and args.confirm_revoked:
        parser.error(
            "Verification and manual confirmation must be separate commands."
        )

    if args.confirm_revoked and not args.evidence_sha256:
        parser.error("--evidence-sha256 is required with --confirm-revoked.")

    if args.evidence_sha256 and not args.confirm_revoked:
        parser.error("--evidence-sha256 is only valid with --confirm-revoked.")

    if shutil.which("docker") is None:
        parser.error("Docker CLI is unavailable.")

    try:
        execute_workflow(
            verify_revocation_requested=args.verify_revocation,
            confirm_revoked_requested=args.confirm_revoked,
            evidence_sha256=args.evidence_sha256,
        )

    except Exception as error:
        print(f"\n[EXECUTION STOPPED] {error}", file=sys.stderr)

        try:
            current = load_state()
            stage = current["stage"]

            audit(
                "REMEDIATION_EXECUTION_STOPPED",
                error=str(error)[:1000],
                ca_operation_attempted=(stage != "NOT_STARTED"),
                execution_performed=(
                    stage in COMPLETED_OPERATION_STAGES
                ),
                current_stage=stage,
            )

        except Exception:
            pass

        sys.exit(1)


if __name__ == "__main__":
    main()
