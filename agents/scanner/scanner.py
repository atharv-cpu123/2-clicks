
import json
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CERTIFICATE_DIR = PROJECT_ROOT / "sandbox" / "certificates"
REPORT_DIR = Path(__file__).resolve().parent / "reports"
REPORT_FILE = REPORT_DIR / "scan_report.json"

# Scanner policies
EXPIRING_SOON_DAYS = 7
MAX_VALIDITY_DAYS = 398


def add_finding(findings, code, severity, title, description, evidence, recommendation):
    findings.append({
        "code": code,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation
    })


def inspect_certificate(cert_path, now):
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())

    findings = []

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    validity_days = (not_after - not_before).total_seconds() / 86400

    public_key = cert.public_key()
    key_type = type(public_key).__name__
    key_size = getattr(public_key, "key_size", None)

    signature_algorithm = cert.signature_hash_algorithm
    signature_name = (
        signature_algorithm.name if signature_algorithm else "unknown"
    )

    # Extract Subject Alternative Names
    dns_names = []
    ip_addresses = []

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addresses = [
            str(address)
            for address in san.get_values_for_type(x509.IPAddress)
        ]

    except x509.ExtensionNotFound:
        add_finding(
            findings,
            "MISSING_SAN",
            "MEDIUM",
            "Subject Alternative Name missing",
            "The certificate does not contain a SAN extension.",
            "No Subject Alternative Name extension found.",
            "Add the required DNS names or IP addresses to the SAN extension."
        )

    # Certificate validity checks
    if not_before > now:
        add_finding(
            findings,
            "NOT_YET_VALID",
            "HIGH",
            "Certificate is not yet valid",
            "The certificate validity period has not started.",
            f"Valid from: {not_before.isoformat()}",
            "Check the certificate dates and system clock."
        )

    if not_after <= now:
        add_finding(
            findings,
            "EXPIRED_CERTIFICATE",
            "CRITICAL",
            "Certificate has expired",
            "The certificate is past its expiration date.",
            f"Expired at: {not_after.isoformat()}",
            "Request approval to revoke and replace the certificate."
        )

    elif not_after - now <= timedelta(days=EXPIRING_SOON_DAYS):
        add_finding(
            findings,
            "EXPIRING_SOON",
            "HIGH",
            "Certificate is expiring soon",
            f"The certificate expires within {EXPIRING_SOON_DAYS} days.",
            f"Expires at: {not_after.isoformat()}",
            "Plan certificate renewal before expiration."
        )

    # Weak public key checks
    if isinstance(public_key, rsa.RSAPublicKey) and key_size < 2048:
        add_finding(
            findings,
            "WEAK_RSA_KEY",
            "HIGH",
            "RSA key is too small",
            "RSA keys smaller than 2048 bits do not meet this scanner's policy.",
            f"RSA key size: {key_size} bits",
            "Replace the certificate with an RSA key of at least 2048 bits or an approved alternative."
        )

    elif isinstance(public_key, dsa.DSAPublicKey) and key_size < 2048:
        add_finding(
            findings,
            "WEAK_DSA_KEY",
            "HIGH",
            "DSA key is too small",
            "DSA keys smaller than 2048 bits do not meet this scanner's policy.",
            f"DSA key size: {key_size} bits",
            "Replace the key using an approved modern algorithm."
        )

    elif isinstance(public_key, ec.EllipticCurvePublicKey) and key_size < 224:
        add_finding(
            findings,
            "WEAK_EC_KEY",
            "HIGH",
            "Elliptic curve key is too small",
            "The elliptic curve key is below this scanner's minimum policy.",
            f"EC key size: {key_size} bits",
            "Replace the key with an approved stronger elliptic curve."
        )

    # Weak signature algorithm checks
    if signature_name.lower() in ("sha1", "md5"):
        add_finding(
            findings,
            "WEAK_SIGNATURE_ALGORITHM",
            "HIGH",
            "Weak signature hash algorithm",
            "SHA-1 and MD5 are not accepted by this scanner's security policy.",
            f"Signature hash: {signature_name}",
            "Reissue the certificate using SHA-256 or a stronger approved hash."
        )

    # Self-issued certificate indicator
    if cert.subject == cert.issuer:
        add_finding(
            findings,
            "SELF_ISSUED_CERTIFICATE",
            "MEDIUM",
            "Subject and issuer are identical",
            "The certificate is self-issued based on matching subject and issuer names. This alone does not prove its signature is self-signed.",
            f"Subject: {cert.subject.rfc4514_string()}",
            "Verify whether this certificate is explicitly trusted and whether a CA-issued certificate is required."
        )

    # Excessive validity period
    if validity_days > MAX_VALIDITY_DAYS:
        add_finding(
            findings,
            "LONG_VALIDITY_PERIOD",
            "MEDIUM",
            "Certificate validity period is unusually long",
            f"The certificate exceeds the configured {MAX_VALIDITY_DAYS}-day policy.",
            f"Validity: {validity_days:.1f} days",
            "Use a shorter certificate validity period."
        )

    # Final certificate record
    return {
        "certificate": cert_path.name,
        "path": str(cert_path.relative_to(PROJECT_ROOT)),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "validity_days": round(validity_days, 2),
        "public_key_algorithm": key_type,
        "public_key_size": key_size,
        "signature_hash_algorithm": signature_name,
        "san_dns_names": dns_names,
        "san_ip_addresses": ip_addresses,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "findings": findings
    }


def main():
    print("\n========== PKI SECURITY SCANNER ==========\n")

    if not CERTIFICATE_DIR.exists():
        raise FileNotFoundError(
            f"Certificate directory not found: {CERTIFICATE_DIR}"
        )

    certificate_files = sorted(CERTIFICATE_DIR.rglob("*.crt"))

    if not certificate_files:
        print("No certificates found.")
        return

    now = datetime.now(timezone.utc)

    certificates = []
    scan_errors = []

    for cert_path in certificate_files:
        try:
            result = inspect_certificate(cert_path, now)
            certificates.append(result)

            print(f"[SCANNED] {cert_path.name} "
                  f"({len(result['findings'])} findings)")

        except Exception as error:
            scan_errors.append({
                "certificate": str(cert_path.relative_to(PROJECT_ROOT)),
                "error": str(error)
            })
            print(f"[ERROR] {cert_path.name}: {error}")

    all_findings = [
        finding
        for certificate in certificates
        for finding in certificate["findings"]
    ]

    severity_counts = Counter(
        finding["severity"] for finding in all_findings
    )

    report = {
        "scan_id": now.strftime("PKI-%Y%m%d-%H%M%S"),
        "scanned_at": now.isoformat(),
        "certificates_scanned": len(certificates),
        "scan_errors_count": len(scan_errors),
        "policy": {
            "expiring_soon_days": EXPIRING_SOON_DAYS,
            "maximum_validity_days": MAX_VALIDITY_DAYS,
            "minimum_rsa_key_size": 2048
        },
        "summary": {
            "total_findings": len(all_findings),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"]
        },
        "certificates": certificates,
        "scan_errors": scan_errors
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    REPORT_FILE.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\n========== SCAN SUMMARY ==========")
    print(f"Certificates scanned: {len(certificates)}")
    print(f"Scan errors: {len(scan_errors)}")
    print(f"Total findings: {len(all_findings)}")
    print(f"Critical: {severity_counts['CRITICAL']}")
    print(f"High: {severity_counts['HIGH']}")
    print(f"Medium: {severity_counts['MEDIUM']}")
    print(f"Low: {severity_counts['LOW']}")
    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
