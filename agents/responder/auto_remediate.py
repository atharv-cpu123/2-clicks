"""Automatically replace medium-only findings in the local PKI sandbox.

This tool is intentionally limited to certificates under sandbox/certificates.
It keeps a timestamped copy of the old certificate before replacing it.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[2]
CERT_ROOT = (ROOT / "sandbox" / "certificates").resolve()
SCAN_REPORT = ROOT / "agents/scanner/reports/scan_report.json"
RISK_REPORT = ROOT / "agents/risk-analyst/reports/risk_report.json"
REPORTS = ROOT / "agents/responder/reports"
PLAN_FILE = REPORTS / "remediation_plan.json"
AUDIT = REPORTS / "audit_log.jsonl"
NOTIFICATIONS = REPORTS / "operator_notifications.jsonl"
CA_CONTAINER = "pki-local-ca"
CA_URL = "https://localhost:9000"
CA_ROOT = "/home/step/certs/root_ca.crt"
CA_PASSWORD = "/home/step/secrets/password"


def now_text():
    return datetime.now(timezone.utc).isoformat()


def record(path, event, **fields):
    REPORTS.mkdir(parents=True, exist_ok=True)
    entry = {"timestamp": now_text(), "event": event, "certificate": path, **fields}
    with AUDIT.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry) + "\n")


def notify(path, message, **fields):
    REPORTS.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": now_text(), "event": "AUTO_REMEDIATION_COMPLETED",
        "certificate": path, "message": message,
        "notification_type": "LOCAL_AUDIT_NOTIFICATION", **fields,
    }
    with NOTIFICATIONS.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry) + "\n")
    print(f"[NOTIFICATION] {message}")


def load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def cert_sans(cert):
    try:
        value = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        value = None
    names = []
    if value:
        names.extend(value.get_values_for_type(x509.DNSName))
        names.extend(str(ip) for ip in value.get_values_for_type(x509.IPAddress))
    if not names:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            names.append(cn[0].value)
    return names


def issue_and_replace(item, event="AUTO_MEDIUM_REMEDIATION_COMPLETED", notify_completion=True):
    relative = Path(item["path"])
    source = (ROOT / relative).resolve()
    if not source.is_relative_to(CERT_ROOT) or not source.is_file():
        raise ValueError("Certificate is missing or outside sandbox/certificates")
    if source.suffix.lower() != ".crt":
        raise ValueError("Only .crt certificates are supported")

    original = load_cert(source)
    common_names = original.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_names:
        raise ValueError("Certificate has no common name to use for reissuance")
    subject = common_names[0].value
    sans = cert_sans(original)
    if not sans:
        raise ValueError("No DNS/IP name can be safely copied to replacement")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = ROOT / "sandbox" / "auto-remediation-backups" / relative.parent.relative_to("sandbox/certificates") / f"{source.stem}-{stamp}.crt"
    key_path = source.with_suffix(".key")
    key_backup = backup.with_suffix(".key")
    staging_cert = source.with_name(f".{source.stem}.auto-{stamp}.crt")
    staging_key = source.with_name(f".{source.stem}.auto-{stamp}.key")
    container_dir = "/certificates/" + relative.parent.as_posix().removeprefix("sandbox/certificates/")
    args = [
        "docker", "exec", CA_CONTAINER, "step", "ca", "certificate",
        subject, f"{container_dir}/{staging_cert.name}", f"{container_dir}/{staging_key.name}",
        "--kty=RSA", "--size=2048", "--not-after=192h",
        "--provisioner=admin@pki.local", f"--provisioner-password-file={CA_PASSWORD}",
        f"--ca-url={CA_URL}", f"--root={CA_ROOT}",
    ]
    args.extend(f"--san={name}" for name in sans)
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "Step CA issuance failed")[-1200:])

    try:
        replacement = load_cert(staging_cert)
        private_key = serialization.load_pem_private_key(staging_key.read_bytes(), password=None)
        if replacement.subject != original.subject:
            raise ValueError("Replacement subject does not match original")
        if replacement.issuer == replacement.subject:
            raise ValueError("Replacement is self-issued instead of CA-issued")
        if private_key.public_key().public_numbers() != replacement.public_key().public_numbers():
            raise ValueError("Replacement certificate and private key do not match")
        verify = subprocess.run(
            ["docker", "exec", CA_CONTAINER, "step", "certificate", "verify",
             f"{container_dir}/{staging_cert.name}", "--roots", CA_ROOT],
            capture_output=True, text=True, check=False,
        )
        if verify.returncode:
            raise RuntimeError((verify.stderr or verify.stdout or "Chain verification failed")[-1200:])

        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, backup)
        if key_path.exists():
            shutil.copy2(key_path, key_backup)
        os.replace(staging_cert, source)
        os.replace(staging_key, key_path)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        record(item["path"], event,
               original_serial=format(original.serial_number, "X"),
               replacement_serial=format(replacement.serial_number, "X"),
               backup=str(backup.relative_to(ROOT)),
               replacement_key=str(key_path.relative_to(ROOT)),
               chain_verified=True)
        if notify_completion:
            notify(item["path"], "Sandbox certificate was replaced and verified.",
                   replacement_serial=format(replacement.serial_number, "X"),
                   backup=str(backup.relative_to(ROOT)))
    finally:
        staging_cert.unlink(missing_ok=True)
        staging_key.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Sandbox certificate replacement")
    parser.add_argument(
        "--approved-certificate",
        help="Replace exactly one certificate after its approval is recorded",
    )
    args = parser.parse_args()

    if shutil.which("docker") is None:
        print("[ERROR] Docker CLI not found. Start Docker Desktop and retry.")
        return 2
    if not SCAN_REPORT.is_file() or not RISK_REPORT.is_file():
        print("[ERROR] Run the scan pipeline first; scan/risk report is missing.")
        return 2

    scan = json.loads(SCAN_REPORT.read_text(encoding="utf-8"))
    risk = json.loads(RISK_REPORT.read_text(encoding="utf-8"))
    if scan.get("scan_id") != risk.get("source_scan_id"):
        print("[ERROR] Risk report is stale. Run the full scan pipeline again.")
        return 2

    if args.approved_certificate:
        plan = json.loads(PLAN_FILE.read_text(encoding="utf-8"))
        matches = [
            item for item in plan.get("remediation_items", [])
            if item.get("certificate") == args.approved_certificate
        ]
        if len(matches) != 1:
            print("[ERROR] Certificate missing or ambiguous in the responder plan.")
            return 2
        approved = matches[0]
        if approved.get("approval_status") != "APPROVED" or approved.get("approval_scope") != "TEST_ONLY":
            print("[ERROR] Replacement requires a recorded TEST_ONLY approval.")
            return 2
        if approved.get("remediation_status") == "COMPLETED":
            print("[ERROR] This approved certificate has already been replaced.")
            return 2
        cert_matches = [
            cert for cert in scan.get("certificates", [])
            if cert.get("certificate") == approved.get("certificate")
            and cert.get("path") == approved.get("path")
        ]
        if len(cert_matches) != 1 or cert_matches[0].get("serial_number", "").upper() != approved.get("serial_number", "").upper():
            print("[ERROR] Current scan does not match the approved certificate serial/path.")
            return 2
        issue_and_replace(
            approved,
            event="APPROVED_CERTIFICATE_REPLACED",
            notify_completion=False,
        )
        approved["remediation_status"] = "COMPLETED"
        temporary = PLAN_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, PLAN_FILE)
        print("[SUCCESS] Approved certificate replaced, verified, backed up, and logged.")
        return 0

    eligible = []
    skipped = []
    for cert in scan.get("certificates", []):
        findings = cert.get("findings", [])
        if not findings or any(f.get("severity", "LOW").upper() != "MEDIUM" for f in findings):
            continue
        if not any(f.get("severity", "").upper() == "MEDIUM" for f in findings):
            continue
        eligible.append(cert)

    print(f"Medium-only certificates flagged: {len(eligible)}")
    for item in eligible:
        try:
            issue_and_replace(item)
        except Exception as error:
            skipped.append({"path": item.get("path"), "reason": str(error)})
            record(item.get("path", "unknown"), "AUTO_REMEDIATION_SKIPPED", reason=str(error))
            print(f"[SKIPPED] {item.get('path')}: {error}")

    print(f"Automatically replaced: {len(eligible) - len(skipped)}")
    print(f"Skipped for safety/unsupported data: {len(skipped)}")
    print(f"Audit: {AUDIT}")
    print(f"Notifications: {NOTIFICATIONS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
