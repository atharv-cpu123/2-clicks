"""Direct PostgreSQL persistence for scan snapshots and audit events."""
import hashlib
import json
import os
from typing import Any


def configured() -> bool:
    return bool(os.getenv("DATABASE_URL", "").strip())


def connect():
    if not configured():
        raise RuntimeError("DATABASE_URL is not configured in the backend .env file.")
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as error:
        raise RuntimeError("Install the PostgreSQL driver with: py -m pip install 'psycopg[binary]'") from error
    return psycopg.connect(
        os.environ["DATABASE_URL"],
        sslmode="require",
        connect_timeout=8,
        row_factory=dict_row,
    )


def ensure_schema() -> None:
    statements = [
        """create table if not exists public.pki_scan_runs (
            scan_id text primary key,
            scanned_at timestamptz not null default now(),
            health_score numeric,
            health_status text,
            scan_report jsonb not null,
            risk_report jsonb not null
        )""",
        """create table if not exists public.pki_certificates (
            scan_id text not null references public.pki_scan_runs(scan_id) on delete cascade,
            certificate_path text not null,
            certificate_name text not null,
            serial_number text,
            highest_severity text,
            findings jsonb not null default '[]'::jsonb,
            certificate_data jsonb not null,
            primary key (scan_id, certificate_path)
        )""",
        """create table if not exists public.pki_audit_events (
            event_id text primary key,
            happened_at timestamptz not null default now(),
            event text not null,
            certificate_name text,
            serial_number text,
            event_data jsonb not null
        )""",
        "alter table public.pki_scan_runs enable row level security",
        "alter table public.pki_certificates enable row level security",
        "alter table public.pki_audit_events enable row level security",
        "revoke all on public.pki_scan_runs from anon, authenticated",
        "revoke all on public.pki_certificates from anon, authenticated",
        "revoke all on public.pki_audit_events from anon, authenticated",
    ]
    with connect() as connection:
        for statement in statements:
            connection.execute(statement)


def persist_scan(scan: dict[str, Any], risk: dict[str, Any]) -> None:
    from psycopg.types.json import Jsonb

    scan_id = scan.get("scan_id")
    if not scan_id:
        raise ValueError("Scanner report has no scan_id; cannot store scan in Supabase.")
    with connect() as connection:
        connection.execute(
            """insert into public.pki_scan_runs
            (scan_id, scanned_at, health_score, health_status, scan_report, risk_report)
            values (%s, %s, %s, %s, %s, %s)
            on conflict (scan_id) do update set
              scanned_at=excluded.scanned_at, health_score=excluded.health_score,
              health_status=excluded.health_status, scan_report=excluded.scan_report,
              risk_report=excluded.risk_report""",
            (scan_id, scan.get("scanned_at"), risk.get("health_score"),
             risk.get("health_status"), Jsonb(scan), Jsonb(risk)),
        )
        connection.execute("delete from public.pki_certificates where scan_id=%s", (scan_id,))
        for cert in scan.get("certificates", []):
            findings = cert.get("findings", [])
            severities = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            highest = max(
                (item.get("severity", "").upper() for item in findings),
                key=lambda severity: severities.get(severity, 0),
                default=None,
            )
            connection.execute(
                """insert into public.pki_certificates
                (scan_id, certificate_path, certificate_name, serial_number,
                 highest_severity, findings, certificate_data)
                values (%s,%s,%s,%s,%s,%s,%s)""",
                (scan_id, cert.get("path", cert.get("certificate", "unknown")),
                 cert.get("certificate", "unknown"), cert.get("serial_number"),
                 highest, Jsonb(findings), Jsonb(cert)),
            )


def sync_audit(records: list[dict[str, Any]]) -> None:
    from psycopg.types.json import Jsonb

    with connect() as connection:
        for record in records:
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
            event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            connection.execute(
                """insert into public.pki_audit_events
                (event_id, happened_at, event, certificate_name, serial_number, event_data)
                values (%s, %s, %s, %s, %s, %s)
                on conflict (event_id) do nothing""",
                (event_id, record.get("timestamp"), record.get("event", "UNKNOWN"),
                 record.get("certificate"), record.get("serial_number"), Jsonb(record)),
            )


def latest_scan() -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "select scan_report, risk_report from public.pki_scan_runs order by scanned_at desc limit 1"
        ).fetchone()
    if not row:
        return None
    return {"scan": row["scan_report"], "risk": row["risk_report"]}


def audit_events() -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "select event_data from public.pki_audit_events order by happened_at desc limit 1000"
        ).fetchall()
    return [row["event_data"] for row in rows]
