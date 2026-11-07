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
            con.execute("""CREATE TABLE IF NOT EXISTS investigation_cases (
                id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open', version INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""")
            con.execute('CREATE INDEX IF NOT EXISTS idx_cases_tenant ON investigation_cases(tenant_id, created_at DESC)')
            con.execute("""CREATE TABLE IF NOT EXISTS case_analyses (
                case_id TEXT NOT NULL, analysis_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
                added_at TEXT NOT NULL, PRIMARY KEY(case_id, analysis_id)
            )""")
            con.execute('CREATE INDEX IF NOT EXISTS idx_case_links_tenant ON case_analyses(tenant_id, case_id)')
            con.execute("""CREATE TABLE IF NOT EXISTS case_reviews (
                id TEXT PRIMARY KEY, case_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, decision TEXT NOT NULL, rationale TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            con.execute('CREATE INDEX IF NOT EXISTS idx_reviews_case ON case_reviews(tenant_id, case_id, created_at)')

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


    # Case operations: tenant predicates are enforced at each read/write boundary.
    # Mutations and the corresponding audit entries are committed atomically.
    @staticmethod
    def _audit_in_transaction(con, tenant_id: str, actor_id: str, action: str, object_id: str, now: str):
        con.execute('INSERT INTO audit(tenant_id,actor_id,action,object_id,created_at) VALUES(?,?,?,?,?)',
                    (tenant_id, actor_id, action, object_id, now))

    @staticmethod
    def _case_record(con, case_id: str, tenant_id: str):
        row = con.execute('SELECT id,tenant_id,title,status,version,created_by,created_at,updated_at '
                          'FROM investigation_cases WHERE id=? AND tenant_id=?', (case_id, tenant_id)).fetchone()
        return dict(zip(('id','tenant_id','title','status','version','created_by','created_at','updated_at'), row)) if row else None

    def create_case(self, case_id: str, title: str, analysis_ids: list[str], tenant_id: str, actor_id: str) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as con:
            con.execute('BEGIN IMMEDIATE')
            for analysis_id in analysis_ids:
                if con.execute('SELECT 1 FROM analyses WHERE id=? AND tenant_id=?', (analysis_id, tenant_id)).fetchone() is None:
                    raise LookupError('Analise inexistente para esta organizacao')
            con.execute('INSERT INTO investigation_cases(id,tenant_id,title,status,version,created_by,created_at,updated_at) '
                        'VALUES(?,?,?,?,?,?,?,?)', (case_id, tenant_id, title, 'open', 1, actor_id, now, now))
            for analysis_id in analysis_ids:
                con.execute('INSERT INTO case_analyses(case_id,analysis_id,tenant_id,added_at) VALUES(?,?,?,?)',
                            (case_id, analysis_id, tenant_id, now))
            self._audit_in_transaction(con, tenant_id, actor_id, 'case.created', case_id, now)
        return self.get_case(case_id, tenant_id)

    def get_case(self, case_id: str, tenant_id: str) -> dict | None:
        with self._connection() as con:
            record = self._case_record(con, case_id, tenant_id)
            if record is None:
                return None
            ids = con.execute('SELECT analysis_id FROM case_analyses WHERE case_id=? AND tenant_id=? '
                              'ORDER BY added_at, analysis_id', (case_id, tenant_id)).fetchall()
            reviews = con.execute('SELECT id,actor_id,decision,rationale,created_at FROM case_reviews '
                                  'WHERE case_id=? AND tenant_id=? ORDER BY created_at, id',
                                  (case_id, tenant_id)).fetchall()
        record['analysis_ids'] = [row[0] for row in ids]
        record['reviews'] = [dict(zip(('id','actor_id','decision','rationale','created_at'), row)) for row in reviews]
        return record

    def list_cases(self, tenant_id: str, limit: int = 50) -> list[dict]:
        with self._connection() as con:
            rows = con.execute('SELECT id FROM investigation_cases WHERE tenant_id=? ORDER BY created_at DESC,id DESC LIMIT ?',
                               (tenant_id, limit)).fetchall()
        return [self.get_case(row[0], tenant_id) for row in rows]

    def add_case_analysis(self, case_id: str, analysis_id: str, tenant_id: str, actor_id: str) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as con:
            con.execute('BEGIN IMMEDIATE')
            record = self._case_record(con, case_id, tenant_id)
            if record is None:
                raise LookupError('Caso inexistente')
            if record['status'] == 'closed':
                raise ValueError('Caso encerrado')
            if con.execute('SELECT 1 FROM analyses WHERE id=? AND tenant_id=?', (analysis_id, tenant_id)).fetchone() is None:
                raise LookupError('Analise inexistente para esta organizacao')
            amount = con.execute('SELECT count(*) FROM case_analyses WHERE case_id=? AND tenant_id=?',
                                 (case_id, tenant_id)).fetchone()[0]
            if amount >= 20:
                raise ValueError('Limite de 20 analises por caso')
            if con.execute('SELECT 1 FROM case_analyses WHERE case_id=? AND analysis_id=? AND tenant_id=?',
                           (case_id, analysis_id, tenant_id)).fetchone():
                raise ValueError('Analise ja vinculada')
            con.execute('INSERT INTO case_analyses(case_id,analysis_id,tenant_id,added_at) VALUES(?,?,?,?)',
                        (case_id, analysis_id, tenant_id, now))
            con.execute('UPDATE investigation_cases SET version=version+1,updated_at=? WHERE id=? AND tenant_id=?',
                        (now, case_id, tenant_id))
            self._audit_in_transaction(con, tenant_id, actor_id, 'case.analysis_linked', case_id, now)
        return self.get_case(case_id, tenant_id)

    def review_case(self, case_id: str, review_id: str, decision: str, rationale: str,
                    tenant_id: str, actor_id: str) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as con:
            con.execute('BEGIN IMMEDIATE')
            record = self._case_record(con, case_id, tenant_id)
            if record is None:
                raise LookupError('Caso inexistente')
            if record['status'] == 'closed':
                raise ValueError('Caso encerrado')
            con.execute('INSERT INTO case_reviews(id,case_id,tenant_id,actor_id,decision,rationale,created_at) '
                        'VALUES(?,?,?,?,?,?,?)', (review_id, case_id, tenant_id, actor_id, decision, rationale, now))
            con.execute('UPDATE investigation_cases SET status=?,version=version+1,updated_at=? '
                        'WHERE id=? AND tenant_id=?', ('under_review', now, case_id, tenant_id))
            self._audit_in_transaction(con, tenant_id, actor_id, 'case.reviewed', case_id, now)
        return self.get_case(case_id, tenant_id)

    def update_case_status(self, case_id: str, status: str, expected_version: int,
                           tenant_id: str, actor_id: str) -> dict:
        permitted = {
            'open': {'triage','under_review','closed'},
            'triage': {'under_review','closed'},
            'under_review': {'triage','closed'},
            'closed': {'under_review'},
        }
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as con:
            con.execute('BEGIN IMMEDIATE')
            record = self._case_record(con, case_id, tenant_id)
            if record is None:
                raise LookupError('Caso inexistente')
            if record['version'] != expected_version:
                raise ValueError('Versao desatualizada')
            if status not in permitted[record['status']]:
                raise ValueError('Transicao de estado nao permitida')
            con.execute('UPDATE investigation_cases SET status=?,version=version+1,updated_at=? WHERE id=? AND tenant_id=?',
                        (status, now, case_id, tenant_id))
            self._audit_in_transaction(con, tenant_id, actor_id, 'case.status_changed', case_id, now)
        return self.get_case(case_id, tenant_id)

    def get_case_records(self, case_id: str, tenant_id: str) -> tuple[dict, list[tuple[dict, dict]]] | None:
        case = self.get_case(case_id, tenant_id)
        if case is None:
            return None
        records: list[tuple[dict, dict]] = []
        for identifier in case['analysis_ids']:
            saved = self.get(identifier, tenant_id)
            if saved is None:
                # Inconsistent storage must never return silently incomplete dossiers.
                raise RuntimeError('Analise vinculada nao encontrada')
            records.append(saved)
        return case, records
