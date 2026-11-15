"""Set the local sandbox CA limit needed for eight-day replacements."""
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "sandbox" / "ca" / "config" / "ca.json"


def main():
    if not CONFIG.is_file():
        raise SystemExit("CA config not found. Start the sandbox CA once, then rerun this script.")
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    authority = config.setdefault("authority", {})
    claims = authority.setdefault("claims", {})
    claims["defaultTLSCertDuration"] = "24h"
    claims["maxTLSCertDuration"] = "240h"
    provisioners = authority.get("provisioners", [])
    admin = [item for item in provisioners if item.get("name") == "admin@pki.local"]
    if len(admin) != 1:
        raise SystemExit("Expected exactly one admin@pki.local provisioner in the local CA config.")
    admin_claims = admin[0].setdefault("claims", {})
    admin_claims["defaultTLSCertDuration"] = "24h"
    admin_claims["maxTLSCertDuration"] = "240h"
    temp = CONFIG.with_suffix(".tmp")
    temp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, CONFIG)
    print("Configured the local CA and admin provisioner maximum lifetime to 240h (10 days).")
    print("Restart pki-local-ca before issuing an eight-day replacement.")


if __name__ == "__main__":
    main()
