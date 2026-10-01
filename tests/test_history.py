"""Scan history, the API, and the history command. These need a real PostgreSQL database."""

import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cloudsentry import rules, store
from cloudsentry.api import app
from cloudsentry.cli import main

DB = os.environ.get("CLOUDSENTRY_TEST_DB")
FIXTURES = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.skipif(not DB, reason="set CLOUDSENTRY_TEST_DB to a PostgreSQL URL to run these")
SOURCE = "aws:us-east-1"


@pytest.fixture
def conn():
    with store.connect(DB) as conn:
        conn.execute("TRUNCATE scans, findings RESTART IDENTITY")
        conn.commit()
        yield conn


def finding(control: str, resource: str) -> rules.Finding:
    return rules.Finding(control, resource, "us-east-1", "detail")


def pairs(rows: list[dict]) -> list[tuple[str, str]]:
    return [(r["control"], r["resource"]) for r in rows]


def test_first_scan_is_all_new(conn):
    store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1")])
    diff = store.changes(conn, SOURCE)
    assert pairs(diff["new"]) == [("CIS 5.3", "sg-1")]
    assert diff["fixed"] == []


def test_new_and_fixed_between_the_last_two_scans(conn):
    store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1"), finding("CIS 3.7", "vpc-1")])
    store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1"), finding("CIS 5.7", "i-1")])
    diff = store.changes(conn, SOURCE)
    assert pairs(diff["new"]) == [("CIS 5.7", "i-1")]
    assert pairs(diff["fixed"]) == [("CIS 3.7", "vpc-1")]


def test_sources_do_not_mix(conn):
    store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1")])
    store.save(conn, "plan:lab.json", [])
    assert pairs(store.changes(conn, SOURCE)["new"]) == [("CIS 5.3", "sg-1")]
    assert store.latest_source(conn) == "plan:lab.json"


def test_open_findings_keep_their_first_seen_time(conn):
    first = store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1")])
    second = store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1"), finding("CIS 5.7", "i-1")])
    times = {r["id"]: r["scanned_at"] for r in conn.execute("SELECT id, scanned_at FROM scans").fetchall()}
    rows = {(r["control"], r["resource"]): r["first_seen"] for r in store.open_findings(conn, SOURCE)}
    assert rows == {("CIS 5.3", "sg-1"): times[first], ("CIS 5.7", "i-1"): times[second]}


def test_trend_counts_by_severity(conn):
    store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1"), finding("CIS 5.6", "rtb-1"), finding("CIS 3.7", "vpc-1")])
    store.save(conn, SOURCE, [])
    latest, older = store.trend(conn)
    assert (latest["high"], latest["medium"], latest["low"]) == (0, 0, 0)
    assert (older["high"], older["medium"], older["low"]) == (1, 1, 1)


def test_api(conn, monkeypatch):
    monkeypatch.setenv("CLOUDSENTRY_DB", DB)
    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/findings").status_code == 404

    store.save(conn, SOURCE, [finding("CIS 5.3", "sg-1")])
    store.save(conn, SOURCE, [finding("CIS 5.7", "i-1")])
    assert [s["id"] for s in client.get("/scans").json()] == [2, 1]
    assert pairs(client.get("/findings").json()["findings"]) == [("CIS 5.7", "i-1")]
    changes = client.get("/changes", params={"source": SOURCE}).json()
    assert pairs(changes["new"]) == [("CIS 5.7", "i-1")]
    assert pairs(changes["fixed"]) == [("CIS 5.3", "sg-1")]


def test_scan_saves_history_and_history_reports_the_fix(conn, tmp_path, capsys):
    lab = tmp_path / "lab.json"
    shutil.copy(FIXTURES / "plan-faults.json", lab)
    main(["scan", "--plan", str(lab), "--db", DB])
    shutil.copy(FIXTURES / "plan-clean.json", lab)
    main(["scan", "--plan", str(lab), "--db", DB])
    out = capsys.readouterr().out
    assert "Saved scan 1 of plan:lab.json: 10 new, 0 fixed" in out
    assert "Saved scan 2 of plan:lab.json: 0 new, 10 fixed" in out

    assert main(["history", "--db", DB]) == 0
    assert "Since the previous scan of plan:lab.json: 0 new, 10 fixed" in capsys.readouterr().out
