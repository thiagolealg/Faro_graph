"""SQLite persistence with tenant isolation, transactional quota and audit trail.

No HTML, full query strings or secret API keys are stored in this database.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path


class Storage:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as con:
            con.execute('CREATE TABLE IF NOT EXISTS analyses (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL, graph TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT "local")')
            cols = {row[1] for row in con.execute('PRAGMA table_info(analyses)')}
            if 'tenant_id' not in cols:
                con.execute('ALTER TABLE analyses ADD COLUMN tenant_id TEXT NOT NULL DEFAULT "local"')
            con.execute('CREATE INDEX IF NOT EXISTS idx_analyses_tenant_created ON analyses(tenant_id, created_at DESC)')
            con.execute('CREATE TABLE IF NOT EXISTS usage (tenant_id TEXT NOT NULL, bucket INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(tenant_id,bucket))')
            con.execute('CREATE TABLE IF NOT EXISTS request_usage (tenant_id TEXT NOT NULL, bucket INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(tenant_id,bucket))')
            con.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT, created_at TEXT NOT NULL)')
            con.execute('CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit(tenant_id, created_at DESC)')

    def _connection(self):
        return sqlite3.connect(self.path, timeout=10)

    def consume_analysis_quota(self, tenant_id: str, hourly_quota: int) -> bool:
        bucket = int(time.time() // 3600)
        with self._connection() as con:
            con.execute('BEGIN IMMEDIATE')
            n = con.execute('SELECT count FROM usage WHERE tenant_id=? AND bucket=?', (tenant_id, bucket)).fetchone()
            if n and n[0] >= hourly_quota:
                return False
            con.execute('INSERT INTO usage(tenant_id,bucket,count) VALUES(?,?,1) ON CONFLICT(tenant_id,bucket) DO UPDATE SET count=count+1', (tenant_id, bucket))
            return True

    def consume_request_quota(self, tenant_id: str, max_per_minute: int) -> bool:
        bucket = int(time.time() // 60)
        with self._connection() as con:
            con.execute('BEGIN IMMEDIATE')
            n = con.execute('SELECT count FROM request_usage WHERE tenant_id=? AND bucket=?', (tenant_id, bucket)).fetchone()
            if n and n[0] >= max_per_minute:
                return False
            con.execute('INSERT INTO request_usage(tenant_id,bucket,count) VALUES(?,?,1) ON CONFLICT(tenant_id,bucket) DO UPDATE SET count=count+1', (tenant_id,bucket))
            return True

    def audit(self, tenant_id: str, actor_id: str, action: str, object_id: str | None = None):
        with self._connection() as con:
            con.execute('INSERT INTO audit(tenant_id,actor_id,action,object_id,created_at) VALUES(?,?,?,?,?)', (tenant_id, actor_id, action, object_id, datetime.now(timezone.utc).isoformat()))

    def list_audit(self, tenant_id: str, limit: int = 100):
        with self._connection() as con:
            rows = con.execute('SELECT actor_id,action,object_id,created_at FROM audit WHERE tenant_id=? ORDER BY id DESC LIMIT ?', (tenant_id, limit)).fetchall()
        return [dict(zip(('actor_id','action','object_id','created_at'), row)) for row in rows]

    def save(self, result: dict, graph: dict, tenant_id: str = 'local'):
        with self._connection() as con:
            con.execute('INSERT INTO analyses(id,created_at,payload,graph,tenant_id) VALUES(?,?,?,?,?)', (result['analysis_id'],result['created_at'],json.dumps(result,ensure_ascii=False),json.dumps(graph,ensure_ascii=False),tenant_id))

    def get(self, identifier: str, tenant_id: str = 'local'):
        with self._connection() as con:
            row = con.execute('SELECT payload,graph FROM analyses WHERE id=? AND tenant_id=?', (identifier,tenant_id)).fetchone()
        return (json.loads(row[0]), json.loads(row[1])) if row else None

    def list(self, limit: int, tenant_id: str = 'local'):
        with self._connection() as con:
            rows = con.execute('SELECT payload FROM analyses WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?', (tenant_id,limit)).fetchall()
        return [json.loads(r[0]) for r in rows]
