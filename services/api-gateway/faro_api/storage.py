"""Persistencia SQLite para MVP local: conexoes por operacao, sem dados brutos de HTML."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path


class Storage:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as con:
            con.execute("CREATE TABLE IF NOT EXISTS analyses (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL, graph TEXT NOT NULL)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC)")

    def _connection(self):
        return sqlite3.connect(self.path, timeout=10)

    def save(self, result: dict, graph: dict):
        with self._connection() as con:
            con.execute("INSERT INTO analyses(id, created_at, payload, graph) VALUES (?, ?, ?, ?)", (result["analysis_id"], result["created_at"], json.dumps(result, ensure_ascii=False), json.dumps(graph, ensure_ascii=False)))

    def get(self, identifier: str):
        with self._connection() as con:
            row = con.execute("SELECT payload, graph FROM analyses WHERE id=?", (identifier,)).fetchone()
        return (json.loads(row[0]), json.loads(row[1])) if row else None

    def list(self, limit: int):
        with self._connection() as con:
            rows = con.execute("SELECT payload FROM analyses ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]
