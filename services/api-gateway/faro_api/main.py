"""API FastAPI do MVP. Nao acessa websites remotos nem afirma autoria de fraudes."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from .auth import Principal, build_registry
from .graph import build_graph
from .risk import evaluate
from .schemas import AnalysisRequest, AnalysisResult, GraphResult
from .storage import Storage
from .url_security import URLValidationError, normalize_url

ROOT = Path(__file__).resolve().parents[3]


def create_app(db_path: str | None = None, api_key: str | None = None, tenants_json: str | None = None) -> FastAPI:
    configured_key = api_key if api_key is not None else os.getenv("FARO_API_KEY", "")
    registry = build_registry(configured_key, tenants_json)
    db = Storage(db_path or os.getenv("FARO_DB_PATH", str(ROOT / ".local" / "faro.sqlite3")))
    app = FastAPI(title="FARO — MVP OSINT & Antiphishing", version="0.2.0", description="Motor lexical offline, HTML opcional fornecido pelo usuario, grafo de indicadores sem atribuicao de pessoas.")

    def require_key(x_faro_api_key: str | None = Header(default=None)) -> Principal:
        principal = registry.resolve(x_faro_api_key)
        if principal is None:
            raise HTTPException(status_code=401, detail="Credencial de API ausente ou invalida")
        return principal

    def require_analyst(principal: Principal = Depends(require_key)) -> Principal:
        if principal.role not in {"analyst", "admin"}:
            raise HTTPException(status_code=403, detail="Permissao de analise necessaria")
        return principal

    def require_admin(principal: Principal = Depends(require_key)) -> Principal:
        if principal.role != "admin":
            raise HTTPException(status_code=403, detail="Permissao administrativa necessaria")
        return principal

    @app.get("/healthz", tags=["operations"])
    def healthz():
        return {"status": "ok", "version": "0.2.0", "remote_fetch_enabled": False}

    @app.post("/v1/analyses", response_model=AnalysisResult, status_code=201, tags=["analysis"])
    def analyze(request: AnalysisRequest, principal: Principal = Depends(require_analyst)):
        try:
            target = normalize_url(request.url)
        except URLValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not db.consume_analysis_quota(principal.tenant_id, principal.hourly_quota):
            raise HTTPException(status_code=429, detail="Quota horaria de analises excedida")
        assessment, evidence, extras = evaluate(target, request.observed_html)
        analysis_id = str(uuid.uuid4())
        result = AnalysisResult(
            analysis_id=analysis_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            normalized_url=target.url,
            hostname=target.hostname,
            registrable_domain=target.registrable_domain,
            assessment=assessment,
            evidence=evidence,
            limitations=[
                "Nao ha coleta remota de paginas, consultas RDAP, DNS ou feeds de ameaca nesta entrega.",
                "HTML opcional e fornecido pelo solicitante e nao e uma evidencia independente.",
                "A pontuacao e heuristica, nao uma probabilidade calibrada ou confirmacao de fraude.",
                "O grafo representa indicadores observados/hipoteses, nao responsaveis identificados.",
            ],
        )
        graph = build_graph(analysis_id, target.url, target.hostname, target.registrable_domain, [e.model_dump() for e in evidence], extras)
        db.save(result.model_dump(), graph.model_dump(), tenant_id=principal.tenant_id)
        db.audit(principal.tenant_id, principal.actor_id, "analysis.created", analysis_id)
        return result

    @app.get("/v1/analyses", response_model=list[AnalysisResult], tags=["analysis"])
    def list_analyses(limit: int = Query(default=20, ge=1, le=100), principal: Principal = Depends(require_key)):
        return db.list(limit, tenant_id=principal.tenant_id)

    @app.get("/v1/analyses/{analysis_id}", response_model=AnalysisResult, tags=["analysis"])
    def get_analysis(analysis_id: uuid.UUID, principal: Principal = Depends(require_key)):
        saved = db.get(str(analysis_id), tenant_id=principal.tenant_id)
        if not saved:
            raise HTTPException(status_code=404, detail="Analise inexistente")
        return saved[0]

    @app.get("/v1/analyses/{analysis_id}/evidence", tags=["analysis"])
    def get_evidence(analysis_id: uuid.UUID, principal: Principal = Depends(require_key)):
        saved = db.get(str(analysis_id), tenant_id=principal.tenant_id)
        if not saved:
            raise HTTPException(status_code=404, detail="Analise inexistente")
        return {"analysis_id": str(analysis_id), "evidence": saved[0]["evidence"]}

    @app.get("/v1/analyses/{analysis_id}/graph", response_model=GraphResult, tags=["graph"])
    def get_graph(analysis_id: uuid.UUID, principal: Principal = Depends(require_key)):
        saved = db.get(str(analysis_id), tenant_id=principal.tenant_id)
        if not saved:
            raise HTTPException(status_code=404, detail="Analise inexistente")
        return saved[1]

    @app.get("/v1/audit", dependencies=[Depends(require_admin)], tags=["operations"])
    def get_audit(limit: int = Query(default=100, ge=1, le=500), principal: Principal = Depends(require_admin)):
        return {"events": db.list_audit(principal.tenant_id, limit=limit)}

    ui_path = ROOT / "apps" / "consumer-web"
    if ui_path.is_dir():
        app.mount("/", StaticFiles(directory=ui_path, html=True), name="web")
    return app


# Variavel para execucao com `uvicorn faro_api.main:app`.
# Testes usam create_app(db_path=..., api_key=...) para isolamento.
if os.getenv("FARO_API_KEY"):
    app = create_app()
else:
    app = None
