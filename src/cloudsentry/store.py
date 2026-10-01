"""Scan history in PostgreSQL: one row per scan and one row per finding.

History is what turns a scan into monitoring: what is new since the last scan, what got fixed,
and how long each open finding has been there.
"""

from __future__ import annotations

import psycopg
from psycopg.rows import dict_row

from cloudsentry.rules import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source     TEXT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id  BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    control  TEXT NOT NULL,
    severity TEXT NOT NULL,
    resource TEXT NOT NULL,
    region   TEXT NOT NULL,
    detail   TEXT NOT NULL,
    PRIMARY KEY (scan_id, control, resource)
);

CREATE INDEX IF NOT EXISTS findings_by_resource ON findings (control, resource);
"""

# Rows of scan a that have no match in scan b. Run a=latest, b=previous for new findings, and
# the other way around for fixed ones.
ONLY_IN = """
SELECT a.control, a.severity, a.resource, a.detail
FROM findings a
WHERE a.scan_id = %(a)s
  AND NOT EXISTS (
      SELECT 1 FROM findings b
      WHERE b.scan_id = %(b)s AND b.control = a.control AND b.resource = a.resource
  )
ORDER BY a.control, a.resource
"""


def connect(url: str) -> psycopg.Connection:
    conn = psycopg.connect(url, row_factory=dict_row)
    conn.execute(SCHEMA)
    conn.commit()
    return conn


def save(conn: psycopg.Connection, source: str, findings: list[Finding]) -> int:
    with conn.transaction():
        scan_id = conn.execute("INSERT INTO scans (source) VALUES (%s) RETURNING id", (source,)).fetchone()["id"]
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO findings (scan_id, control, severity, resource, region, detail) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [(scan_id, f.control, f.severity, f.resource, f.region, f.detail) for f in findings],
            )
    return scan_id


def latest_source(conn: psycopg.Connection) -> str | None:
    row = conn.execute("SELECT source FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return row["source"] if row else None


def changes(conn: psycopg.Connection, source: str) -> dict[str, list[dict]]:
    """Findings that appeared or disappeared between the two latest scans of one source."""
    rows = conn.execute("SELECT id FROM scans WHERE source = %s ORDER BY id DESC LIMIT 2", (source,)).fetchall()
    if not rows:
        return {"new": [], "fixed": []}
    latest = rows[0]["id"]
    previous = rows[1]["id"] if len(rows) > 1 else None
    new = conn.execute(ONLY_IN, {"a": latest, "b": previous}).fetchall()
    fixed = conn.execute(ONLY_IN, {"a": previous, "b": latest}).fetchall() if previous else []
    return {"new": new, "fixed": fixed}


def open_findings(conn: psycopg.Connection, source: str) -> list[dict]:
    """Findings in the latest scan of a source, with when each one first showed up."""
    return conn.execute(
        """
        WITH latest AS (SELECT max(id) AS id FROM scans WHERE source = %(source)s)
        SELECT f.control, f.severity, f.resource, f.detail, min(s.scanned_at) AS first_seen
        FROM findings f
        JOIN latest ON f.scan_id = latest.id
        JOIN findings h ON h.control = f.control AND h.resource = f.resource
        JOIN scans s ON s.id = h.scan_id AND s.source = %(source)s
        GROUP BY f.control, f.severity, f.resource, f.detail
        ORDER BY first_seen, f.control, f.resource
        """,
        {"source": source},
    ).fetchall()


def trend(conn: psycopg.Connection, limit: int = 10) -> list[dict]:
    return conn.execute(
        """
        SELECT s.id, s.source, s.scanned_at,
               count(f.control) FILTER (WHERE f.severity = 'high') AS high,
               count(f.control) FILTER (WHERE f.severity = 'medium') AS medium,
               count(f.control) FILTER (WHERE f.severity = 'low') AS low
        FROM scans s
        LEFT JOIN findings f ON f.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.id DESC
        LIMIT %s
        """,
        (limit,),
    ).fetchall()
