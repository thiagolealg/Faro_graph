"""API FastAPI do MVP. Nao acessa websites remotos nem afirma autoria de fraudes."""
from __future__ import annotations

import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from .graph import build_graph
from .risk import evaluate
from .schemas import AnalysisRequest, AnalysisResult, GraphResult
from .storage import Storage
from .url_security import URLValidationError, normalize_url

ROOT = Path(__file__).resolve().parents[3]


def create_app(db_path: str | None = None, api_key: str | None = None) -> FastAPI:
    configured_key = api_key if api_key is not None else os.getenv("FARO_API_KEY", "")
    if not configured_key:
        raise RuntimeError("FARO_API_KEY obrigatoria: defina uma chave para inicializar a API")
    db = Storage(db_path or os.getenv("FARO_DB_PATH", str(ROOT / ".local" / "faro.sqlite3")))
    app = FastAPI(title="FARO — MVP OSINT & Antiphishing", version="0.1.0", description="Motor lexical offline, HTML opcional fornecido pelo usuario, grafo de indicadores sem atribuicao de pessoas.")

    def require_key(x_faro_api_key: str | None = Header(default=None)):
        if not x_faro_api_key or not secrets.compare_digest(x_faro_api_key, configured_key):
            raise HTTPException(status_code=401, detail="Credencial de API ausente ou invalida")

    @app.get("/healthz", tags=["operations"])
    def healthz():
        return {"status": "ok", "version": "0.1.0", "remote_fetch_enabled": False}

    @app.post("/v1/analyses", response_model=AnalysisResult, status_code=201, dependencies=[Depends(require_key)], tags=["analysis"])
    def analyze(request: AnalysisRequest):
        try:
            target = normalize_url(request.url)
        except URLValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
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
        db.save(result.model_dump(), graph.model_dump())
        return result

    @app.get("/v1/analyses", response_model=list[AnalysisResult], dependencies=[Depends(require_key)], tags=["analysis"])
    def list_analyses(limit: int = Query(default=20, ge=1, le=100)):
        return db.list(limit)

    @app.get("/v1/analyses/{analysis_id}", response_model=AnalysisResult, dependencies=[Depends(require_key)], tags=["analysis"])
    def get_analysis(analysis_id: uuid.UUID):
        saved = db.get(str(analysis_id))
        if not saved:
            raise HTTPException(status_code=404, detail="Analise inexistente")
        return saved[0]

    @app.get("/v1/analyses/{analysis_id}/evidence", dependencies=[Depends(require_key)], tags=["analysis"])
    def get_evidence(analysis_id: uuid.UUID):
        saved = db.get(str(analysis_id))
        if not saved:
            raise HTTPException(status_code=404, detail="Analise inexistente")
        return {"analysis_id": str(analysis_id), "evidence": saved[0]["evidence"]}

    @app.get("/v1/analyses/{analysis_id}/graph", response_model=GraphResult, dependencies=[Depends(require_key)], tags=["graph"])
    def get_graph(analysis_id: uuid.UUID):
        saved = db.get(str(analysis_id))
        if not saved:
            raise HTTPException(status_code=404, detail="Analise inexistente")
        return saved[1]

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
