
import argparse
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Project directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(BASE_DIR, "sandbox", "certificates")

CATEGORIES = [
    "valid",
    "expired",
    "expiring-soon",
    "self-signed",
    "weak"
]

CA_CONTAINER = "pki-local-ca"
CA_PROVISIONER = "admin@pki.local"
CA_PASSWORD_FILE = "/home/step/secrets/password"


def check_dependencies():
    """Check Docker and the local CA needed for CA-issued profiles."""

    try:
        subprocess.run(["docker", "version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise RuntimeError("Docker is not available or Docker Desktop is not running.")

    subprocess.run(
        ["docker", "exec", CA_CONTAINER, "step", "version"],
        capture_output=True,
        check=True
    )

    print("Smallstep CA container is accessible.")
    print("Python cryptography library is available.")


def create_folders():
    """Create certificate category folders."""

    for category in CATEGORIES:
        path = os.path.join(CERT_DIR, category)
        os.makedirs(path, exist_ok=True)
        print(f"Prepared folder: {category}")


def count_certificates(category):
    """Count existing certificate files."""

    folder = os.path.join(CERT_DIR, category)

    return sum(
        1 for filename in os.listdir(folder)
        if filename.endswith(".crt")
    )


def get_missing_certificates(targets):
    """Calculate how many certificates are missing."""

    missing = {}

    print("\nCertificate inventory:")

    for category in CATEGORIES:
        existing = count_certificates(category)
        target = targets[category]

        missing[category] = max(0, target - existing)

        print(
            f"{category}: {existing} existing, "
            f"{missing[category]} remaining"
        )

        if existing > target:
            print(
                f"Warning: {category} exceeds its target. "
                "Existing files will be preserved."
            )

    return missing


def get_next_certificate_name(category, requested_name=None):
    """Choose a unique filename, optionally using a requested safe name."""

    if requested_name:
        for current_root, _, filenames in os.walk(CERT_DIR):
            if f"{requested_name}.crt" in filenames or f"{requested_name}.key" in filenames:
                raise FileExistsError(f"Certificate name already exists: {requested_name}")
        return requested_name

    index = 1

    while True:
        name = f"{category.replace('-', '')}{index:02d}"

        cert_path = os.path.join(
            CERT_DIR, category, f"{name}.crt"
        )

        key_path = os.path.join(
            CERT_DIR, category, f"{name}.key"
        )

        if not os.path.exists(cert_path) and not os.path.exists(key_path):
            return name

        index += 1


def generate_ca_certificate(name, category, not_after):
    """Generate a certificate signed by the local Smallstep CA."""

    cert_path = os.path.join(
        CERT_DIR, category, f"{name}.crt"
    )

    key_path = os.path.join(
        CERT_DIR, category, f"{name}.key"
    )

    command = [
        "docker", "exec", CA_CONTAINER,
        "step", "ca", "certificate",
        f"{name}.pki.local",
        f"/certificates/{category}/{name}.crt",
        f"/certificates/{category}/{name}.key",
        "--san", f"{name}.pki.local",
        "--not-before=-5m",
        f"--not-after={not_after}",
        "--provisioner", CA_PROVISIONER,
        "--provisioner-password-file", CA_PASSWORD_FILE
    ]

    try:
        subprocess.run(command, check=True)

        if os.path.exists(key_path):
            os.chmod(key_path, 0o600)

        print(f"Generated: {name} ({category})")

    except Exception:
        for path in [cert_path, key_path]:
            if os.path.exists(path):
                os.remove(path)
        raise


def generate_weak_certificate(name, category):
    """Generate a deliberately weak RSA-1024/SHA-1 test certificate."""

    output_dir = os.path.join(CERT_DIR, category)

    cert_path = os.path.join(output_dir, f"{name}.crt")
    key_path = os.path.join(output_dir, f"{name}.key")

    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.pki.local")
        ])
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(f"{name}.pki.local")]),
                critical=False,
            )
            .sign(key, hashes.SHA1())
        )
        with open(key_path, "wb") as key_file:
            key_file.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
        os.chmod(key_path, 0o600)
        print(f"Generated: {name} ({category}, RSA 1024-bit, SHA-1)")

    except Exception:
        for path in [cert_path, key_path]:
            if os.path.exists(path):
                os.remove(path)
        raise



def generate_self_signed_certificate(
    name,
    category,
    weak=False,
    expired=False
):
    """Generate normal or expired self-signed certificates."""

    if weak:
        generate_weak_certificate(name, category)
        return

    output_dir = os.path.join(CERT_DIR, category)

    cert_path = os.path.join(output_dir, f"{name}.crt")
    key_path = os.path.join(output_dir, f"{name}.key")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            f"{name}.pki.local"
        )
    ])

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if expired:
        not_before = now - timedelta(days=2)
        not_after = now - timedelta(days=1)
    else:
        not_before = now - timedelta(minutes=5)
        not_after = now + timedelta(days=365)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"{name}.pki.local")
            ]),
            critical=False
        )
        .sign(key, hashes.SHA256())
    )

    try:
        with open(key_path, "wb") as file:
            file.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                )
            )

        os.chmod(key_path, 0o600)

        with open(cert_path, "wb") as file:
            file.write(
                certificate.public_bytes(
                    serialization.Encoding.PEM
                )
            )

    except Exception:
        for path in [cert_path, key_path]:
            if os.path.exists(path):
                os.remove(path)
        raise

    print(
        f"Generated: {name} ({category}, RSA 2048-bit, SHA-256)"
    )


def generate_category_certificate(category, requested_name=None):
    """Generate one certificate according to its category."""

    name = get_next_certificate_name(category, requested_name)

    if category == "valid":
        generate_ca_certificate(
            name, category, "192h"
        )

    elif category == "expiring-soon":
        generate_ca_certificate(
            name, category, "2h"
        )

    elif category == "expired":
        generate_self_signed_certificate(
            name, category, expired=True
        )

    elif category == "self-signed":
        generate_self_signed_certificate(
            name, category
        )

    elif category == "weak":
        generate_self_signed_certificate(
            name, category, weak=True
        )


def main():
    parser = argparse.ArgumentParser(
        description="PKI Mock Certificate Generator"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=30,
        help="Total number of mock certificates (20-50)"
    )

    args = parser.parse_args()

    if args.count < 20 or args.count > 50:
        parser.error(
            "Certificate count must be between 20 and 50."
        )

    base_count, remainder = divmod(
        args.count, len(CATEGORIES)
    )

    targets = {
        category: base_count + (1 if index < remainder else 0)
        for index, category in enumerate(CATEGORIES)
    }

    print(
        f"Preparing to generate {args.count} certificates..."
    )

    try:
        check_dependencies()
        create_folders()

        missing = get_missing_certificates(targets)

        print("\nStarting certificate generation...\n")

        for category in CATEGORIES:
            for _ in range(missing[category]):
                generate_category_certificate(category)

        print("\nFinal certificate inventory:")

        total = 0

        for category in CATEGORIES:
            count = count_certificates(category)
            total += count
            print(f"{category}: {count}")

        print(f"\nTotal certificates: {total}")

        if total == args.count:
            print("Target certificate count achieved.")
        else:
            print(
                "Warning: Actual count differs from target. "
                "Review the inventory."
            )

        print("Certificate generation completed.")

    except (
        RuntimeError,
        subprocess.CalledProcessError,
        OSError,
        ValueError
    ) as error:
        print(f"\nGeneration failed: {error}")
        print("Check the error before running again.")
        sys.exit(1)


if __name__ == "__main__":
    main()
