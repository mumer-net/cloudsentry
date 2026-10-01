"""A small read-only API over scan history."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, HTTPException

from cloudsentry import __version__, store

app = FastAPI(title="CloudSentry", version=__version__)


def db() -> Iterator[psycopg.Connection]:
    with store.connect(os.environ["CLOUDSENTRY_DB"]) as conn:
        yield conn


Db = Annotated[psycopg.Connection, Depends(db)]


def _source(conn: psycopg.Connection, source: str | None) -> str:
    source = source or store.latest_source(conn)
    if source is None:
        raise HTTPException(status_code=404, detail="no scans saved yet")
    return source


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/scans")
def scans(conn: Db, limit: int = 20) -> list[dict]:
    return store.trend(conn, limit)


@app.get("/findings")
def findings(conn: Db, source: str | None = None) -> dict:
    source = _source(conn, source)
    return {"source": source, "findings": store.open_findings(conn, source)}


@app.get("/changes")
def changes(conn: Db, source: str | None = None) -> dict:
    source = _source(conn, source)
    return {"source": source, **store.changes(conn, source)}
