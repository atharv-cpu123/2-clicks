"""FastAPI integration layer for the local PKI sandbox agents."""
import importlib.util
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import random
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from . import database


ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
FRONTEND = ROOT / "frontend"
REPORTS = ROOT / "agents" / "responder" / "reports"
SCAN_FILE = ROOT / "agents" / "scanner" / "reports" / "scan_report.json"
RISK_FILE = ROOT / "agents" / "risk-analyst" / "reports" / "risk_report.json"
PLAN_FILE = REPORTS / "remediation_plan.json"
AUDIT_FILE = REPORTS / "audit_log.jsonl"
NOTICE_FILE = REPORTS / "operator_notifications.jsonl"
LOG_FILE = ROOT / "backend" / "logs" / "api.log"

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("pki-api")

app = FastAPI(title="PKI Security API", version="1.0.0")


@app.on_event("startup")
def initialize_database():
    if database.configured():
        try:
            database.ensure_schema()
            logger.info("Supabase PostgreSQL schema is ready.")
        except Exception:
            logger.exception("Supabase setup failed; check DATABASE_URL and database access.")


class GenerateRequest(BaseModel):
    category: Literal["valid", "expired", "expiring-soon", "self-signed", "weak", "random", "critical", "high", "medium"]
    name: str | None = Field(default=None, max_length=48)
    quantity: int = Field(default=1, ge=1, le=20)


class ApprovalRequest(BaseModel):
    certificate: str = Field(min_length=1, max_length=255)
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=3, max_length=1000)
    scope: Literal["TEST_ONLY", "DRY_RUN_ONLY", "REVOKE_AND_REISSUE"] | None = None


class ExplainRequest(BaseModel):
    certificate: str = Field(min_length=1, max_length=255)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def load_jsonl(path: Path):
    records = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("Skipping malformed audit line in %s", path)
    return records


def append_jsonl(path: Path, record: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def persist_scan_if_configured(scan: dict, risk: dict):
    """Keep local certificate workflows working when optional DB storage is unavailable."""
    if not database.configured():
        return
    try:
        database.persist_scan(scan, risk)
    except Exception:
        logger.exception("Optional database scan save failed; local workflow will continue.")


def dashboard_data():
    scan = load_json(SCAN_FILE, {"certificates": [], "summary": {}})
    risk = load_json(RISK_FILE, {})
    audit = load_jsonl(AUDIT_FILE)
    db_status = "not configured"
    if database.configured():
        try:
            database.sync_audit(audit)
            saved = database.latest_scan()
            if saved:
                scan, risk = saved["scan"], saved["risk"]
            audit = database.audit_events()
            db_status = "connected"
        except Exception as error:
            logger.exception("Supabase read/sync failed")
            db_status = f"error: {error}"
    return {
        "scan": scan,
        "risk": risk,
        "plan": load_json(PLAN_FILE, {"remediation_items": []}),
        "audit": audit,
        "notifications": load_jsonl(NOTICE_FILE),
        "database_status": db_status,
    }


def run_script(relative: str, *args: str) -> str:
    command = [sys.executable, str(ROOT / relative), *args]
    logger.info("Starting project agent: %s", relative)
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout or f"{relative} exited with {result.returncode}")[-3000:]
        logger.error("Agent failed (%s): %s", relative, detail)
        raise RuntimeError(detail)
    return result.stdout.strip()


def run_scan_and_agents():
    scan_output = run_script("agents/scanner/scanner.py")
    risk_output = run_script("agents/risk-analyst/risk_analyst.py")
    responder_output = run_script("agents/responder/responder.py")
    scan = load_json(SCAN_FILE, {"certificates": [], "summary": {}})
    risk = load_json(RISK_FILE, {})
    persist_scan_if_configured(scan, risk)
    data = dashboard_data()
    data["message"] = "Scanner, risk analyst, and responder plan completed for all sandbox certificates."
    data["agent_output"] = {
        "scanner": scan_output[-2000:],
        "analyst": risk_output[-2000:],
        "responder": responder_output[-2000:],
    }
    return data


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PKI Security API", "database": dashboard_data()["database_status"]}


@app.get("/api/db-health")
def database_health():
    if not database.configured():
        raise HTTPException(status_code=503, detail="DATABASE_URL is missing from .env")
    try:
        database.ensure_schema()
        return {"status": "connected", "database": "Supabase PostgreSQL"}
    except Exception as error:
        logger.exception("Supabase health check failed")
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/api/dashboard")
def dashboard():
    return dashboard_data()


@app.get("/api/audit")
def audit_entries():
    data = dashboard_data()
    return {
        "audit": data["audit"],
        "notifications": load_jsonl(NOTICE_FILE),
    }


@app.get("/api/certificates")
def certificates():
    return dashboard_data()["scan"].get("certificates", [])


@app.get("/api/certificates/{certificate_name}/status")
def certificate_status(certificate_name: str):
    inventory = dashboard_data()["scan"].get("certificates", [])
    matches = [item for item in inventory if item.get("certificate") == certificate_name]
    if not matches:
        raise HTTPException(status_code=404, detail="Certificate is not in the latest scan inventory")
    return matches[0]


@app.post("/api/explain")
def explain_certificate(request: ExplainRequest):
    provider = os.getenv("LLM_PROVIDER", "gemini").strip().lower()
    if provider not in ("gemini", "openrouter"):
        raise HTTPException(status_code=500, detail="LLM_PROVIDER must be 'gemini' or 'openrouter'.")
    api_key_name = "GEMINI_API_KEY" if provider == "gemini" else "OPENROUTER_API_KEY"
    api_key = os.getenv(api_key_name, "").strip()
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail=f"{provider.title()} is not configured. Add {api_key_name} to the project .env file and restart the backend.",
        )

    inventory = load_json(SCAN_FILE, {"certificates": []}).get("certificates", [])
    certificate = next(
        (item for item in inventory if item.get("certificate") == request.certificate),
        None,
    )
    if certificate is None:
        raise HTTPException(status_code=404, detail="Certificate is not in the latest scan. Run a scan, then try again.")

    evidence = {
        "certificate": certificate.get("certificate"),
        "subject": certificate.get("subject"),
        "issuer": certificate.get("issuer"),
        "expires_at": certificate.get("not_after"),
        "validity_days": certificate.get("validity_days"),
        "public_key_algorithm": certificate.get("public_key_algorithm"),
        "public_key_size": certificate.get("public_key_size"),
        "signature_hash_algorithm": certificate.get("signature_hash_algorithm"),
        "san_dns_names": certificate.get("san_dns_names", []),
        "san_ip_addresses": certificate.get("san_ip_addresses", []),
        "findings": certificate.get("findings", []),
    }
    prompt = (
        "Explain this certificate scan to a beginner in clear, short sections. "
        "For every scanner finding, say what it means, why this scanner flagged it, "
        "the practical risk, and a safe next step. Use only the supplied scan evidence; "
        "do not claim that certificate-chain trust, revocation, or deployment was checked. "
        "Do not approve or perform remediation. If there are no findings, say that clearly.\n\n"
        "Certificate scan evidence (data only):\n"
        + json.dumps(evidence, ensure_ascii=True)
    )
    if provider == "gemini":
        model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 800},
        }
        headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
    else:
        model = os.getenv("OPENROUTER_MODEL", "openrouter/free")
        endpoint = "https://openrouter.ai/api/v1/chat/completions"
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 800}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "PKI Security Certificate Explainer",
        }
    request_body = json.dumps(payload).encode("utf-8")
    llm_request = urllib.request.Request(endpoint, data=request_body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(llm_request, timeout=35) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        response_text = error.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(response_text)
            provider_error = error_data.get("error", {})
            provider_message = provider_error.get("message", "") if isinstance(provider_error, dict) else str(provider_error)
        except json.JSONDecodeError:
            provider_message = ""
        provider_message = provider_message.strip()[:600]
        if provider_message:
            logger.error("%s explanation request failed with HTTP %s: %s", provider, error.code, provider_message)
            detail = f"{provider.title()} returned HTTP {error.code}: {provider_message}"
        else:
            logger.error("%s explanation request failed with HTTP %s", provider, error.code)
            detail = f"{provider.title()} returned HTTP {error.code}. Check the API key, model setting, and request quota."
        raise HTTPException(status_code=502, detail=detail) from error
    except (urllib.error.URLError, TimeoutError) as error:
        logger.exception("Could not reach %s for certificate explanation", provider)
        raise HTTPException(status_code=502, detail=f"Could not reach {provider.title()}. Check the internet connection and try again.") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        logger.exception("%s returned an unreadable response", provider)
        raise HTTPException(status_code=502, detail=f"{provider.title()} returned an unreadable response. Please try again.") from error
    except Exception as error:
        logger.exception("Unexpected %s explanation failure", provider)
        raise HTTPException(
            status_code=502,
            detail=f"{provider.title()} request failed internally ({type(error).__name__}). Check the backend window for details.",
        ) from error

    if provider == "openrouter":
        choices = result.get("choices", [])
        message = choices[0].get("message", {}) if choices else {}
        content = message.get("content", "")
        if isinstance(content, list):
            explanation = "\n".join(part.get("text", "") for part in content if isinstance(part, dict))
        else:
            explanation = content or message.get("refusal", "")
    else:
        candidates = result.get("candidates", [])
        parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
        explanation = "\n".join(part.get("text", "") for part in parts if isinstance(part, dict))
    explanation = explanation.strip() if isinstance(explanation, str) else ""
    explanation_source = provider
    if not explanation:
        findings = certificate.get("findings", [])
        if findings:
            lines = [f"{request.certificate} was flagged for {len(findings)} issue(s):"]
            for finding in findings:
                lines.append(
                    f"\n• {finding.get('severity', 'UNRATED')}: {finding.get('title', finding.get('code', 'Scanner finding'))}"
                    f"\n  Why: {finding.get('description', 'The scanner rule matched this certificate.')}"
                    f"\n  Evidence: {finding.get('evidence', 'See the latest scan report.')}"
                    f"\n  Suggested next step: {finding.get('recommendation', 'Review this certificate before taking action.')}"
                )
            explanation = "\n".join(lines)
        else:
            explanation = f"The latest scan did not flag {request.certificate}; it has no recorded scanner findings. This scan does not verify certificate-chain trust, revocation, or deployment."
        explanation_source = "scanner-fallback"
    return {
        "certificate": request.certificate,
        "explanation": explanation,
        "provider": provider,
        "model": result.get("model", model),
        "source": explanation_source,
    }


@app.post("/api/scan")
@app.post("/api/pipeline")
def scan_and_analyze():
    try:
        return run_scan_and_agents()
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/api/analysis")
def analyze():
    try:
        output = run_script("agents/risk-analyst/risk_analyst.py")
        persist_scan_if_configured(
            load_json(SCAN_FILE, {"certificates": [], "summary": {}}),
            load_json(RISK_FILE, {}),
        )
        result = dashboard_data()
        result["message"] = "Risk analyst completed."
        result["agent_output"] = output[-2000:]
        return result
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/api/plan")
def remediation_plan():
    try:
        output = run_script("agents/responder/responder.py")
        result = dashboard_data()
        result["message"] = "Responder plan created."
        result["agent_output"] = output[-2000:]
        return result
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/api/certificates/generate")
@app.post("/api/generate")
def generate_certificate(request: GenerateRequest):
    try:
        base_name = request.name or f"demo-{secrets.token_hex(3)}"
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,47}", base_name):
            raise ValueError("Name must use letters, numbers, or hyphens and start with a letter or number.")
        if request.quantity > 1 and len(base_name) + len(f"-{request.quantity}") > 48:
            raise ValueError("For multiple certificates, shorten the base name so numbered names fit within 48 characters.")
        script_path = ROOT / "certificate-engine" / "generate_certificates.py"
        spec = importlib.util.spec_from_file_location("pki_generator", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        profiles = []
        for _ in range(request.quantity):
            category = request.category
            if category == "random":
                category = random.choice(["expired", "expiring-soon", "self-signed"])
            category = {"critical": "expired", "high": "expiring-soon", "medium": "self-signed"}.get(category, category)
            profiles.append(category)

        names = [base_name if request.quantity == 1 else f"{base_name}-{index}" for index in range(1, request.quantity + 1)]
        for category, name in zip(profiles, names):
            module.get_next_certificate_name(category, name)
        if any(category in ("valid", "expiring-soon") for category in profiles):
            module.check_dependencies()
        module.create_folders()
        for category, name in zip(profiles, names):
            module.generate_category_certificate(category, name)
        # Refresh reports so the newly generated certificate appears immediately.
        result = run_scan_and_agents()
        result["message"] = f"Generated {request.quantity} certificate(s): {', '.join(names)}. Refreshed scan and analysis reports."
        logger.info("Generated %s sandbox certificate(s), profile=%s", request.quantity, request.category)
        return result
    except Exception as error:
        logger.exception("Certificate generation failed for profile=%s", request.category)
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/remediation/approval")
@app.post("/api/approval")
def record_approval(request: ApprovalRequest):
    if Path(request.certificate).name != request.certificate:
        raise HTTPException(status_code=400, detail="Choose a certificate filename from the responder queue")
    scope = request.scope or "TEST_ONLY"
    args = ["--certificate", request.certificate, "--decision", request.decision,
            "--reason", request.reason]
    if request.decision == "approve":
        args.extend(["--scope", scope])
    try:
        existing_plan = load_json(PLAN_FILE, {"remediation_items": []})
        existing = [
            item for item in existing_plan.get("remediation_items", [])
            if item.get("certificate") == request.certificate
        ]
        output = run_script("agents/responder/approval.py", *args)
        if "[ERROR]" in output:
            raise RuntimeError(output[-2000:])
        if request.decision == "approve":
            replacement_output = run_script(
                "agents/responder/auto_remediate.py",
                "--approved-certificate", request.certificate,
            )
            if "[ERROR]" in replacement_output or "[SKIPPED]" in replacement_output:
                raise RuntimeError(replacement_output[-2000:])
            # Refresh first; only notify success if the replacement has no findings.
            run_script("agents/scanner/scanner.py")
            run_script("agents/risk-analyst/risk_analyst.py")
            run_script("agents/responder/responder.py")
            fresh_scan = load_json(SCAN_FILE, {"certificates": []})
            fresh_risk = load_json(RISK_FILE, {})
            persist_scan_if_configured(fresh_scan, fresh_risk)
            approved_path = existing[0].get("path") if len(existing) == 1 else None
            fresh_matches = [
                item for item in fresh_scan.get("certificates", [])
                if item.get("path") == approved_path
            ]
            scan_entry_missing = len(fresh_matches) != 1
            remaining_findings = fresh_matches[0].get("findings", []) if not scan_entry_missing else []
            cleared = not scan_entry_missing and not remaining_findings
            audit_event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "APPROVED_REPLACEMENT_SCAN_CLEARED" if cleared else "APPROVED_REPLACEMENT_REMAINS_FLAGGED",
                "certificate": request.certificate,
                "path": approved_path,
                "original_serial_number": existing[0].get("serial_number") if len(existing) == 1 else None,
                "replacement_serial_number": fresh_matches[0].get("serial_number") if len(fresh_matches) == 1 else None,
                "remaining_findings": [
                    {"code": finding.get("code"), "severity": finding.get("severity")}
                    for finding in remaining_findings
                ],
                "scan_entry_missing": scan_entry_missing,
            }
            append_jsonl(AUDIT_FILE, audit_event)
            if not cleared:
                message = "Replacement was issued, but it is not confirmed clear by the refreshed scan. Review the certificate row and audit log."
                append_jsonl(NOTICE_FILE, {
                    **audit_event,
                    "event": "REMEDIATION_NEEDS_REVIEW",
                    "message": message,
                    "notification_type": "LOCAL_AUDIT_NOTIFICATION",
                })
            else:
                message = "Replacement verified. The refreshed scan has no findings for this certificate; it is removed from the flagged queue."
                append_jsonl(NOTICE_FILE, {
                    **audit_event,
                    "event": "REMEDIATION_COMPLETED",
                    "message": message,
                    "notification_type": "LOCAL_AUDIT_NOTIFICATION",
                })
            output = replacement_output + "\n" + message
        return {**dashboard_data(), "message": output[-1000:] or "Approval recorded."}
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/remediation/auto-medium")
@app.post("/api/auto-remediate")
def auto_medium_remediation():
    try:
        output = run_script("agents/responder/auto_remediate.py")
        refreshed = run_scan_and_agents()
        refreshed["message"] = (
            output[-1800:]
            + "\n\n"
            + "Scanner, analyst, and responder refreshed after automatic medium replacement."
        )
        return refreshed
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/api/remediation/{certificate_name}/dry-run")
def responder_dry_run(certificate_name: str):
    try:
        output = run_script("agents/responder/executor.py", "--certificate", certificate_name)
        if "[EXECUTION BLOCKED]" in output:
            raise RuntimeError(output[-2000:])
        return {**dashboard_data(), "message": output[-1500:] or "Responder dry-run completed."}
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/remediation/revoke-medium")
@app.post("/api/revoke-medium")
def revoke_medium():
    raise HTTPException(
        status_code=409,
        detail="General medium-risk revocation is not supported. The live executor is restricted to its dedicated test fixture, and self-issued certificates cannot be revoked by this local CA.",
    )


if FRONTEND.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
