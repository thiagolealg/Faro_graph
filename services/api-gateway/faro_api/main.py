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
from .case_schemas import CaseCreateRequest, CaseLinkRequest, CaseReviewRequest, CaseStatusRequest
from .cases import aggregate_case_graph, build_dossier
from .graph import build_graph
from .passive_dns import PassiveDNSCollector
from .public_intel import RDAPCollector, CertificateTransparencyCollector
from .threat_intel import configured_snapshot
from .risk import evaluate
from .schemas import AnalysisRequest, AnalysisResult, DNSObservation, RDAPObservation, CTObservation, ThreatIntelObservation, Evidence, GraphResult
from .storage import Storage
from .url_security import URLValidationError, normalize_url

ROOT = Path(__file__).resolve().parents[3]


def create_app(db_path: str | None = None, api_key: str | None = None, tenants_json: str | None = None) -> FastAPI:
    configured_key = api_key if api_key is not None else os.getenv("FARO_API_KEY", "")
    registry = build_registry(configured_key, tenants_json)
    requests_per_minute = int(os.getenv("FARO_REQUESTS_PER_MINUTE", "120"))
    if not 1 <= requests_per_minute <= 100_000:
        raise RuntimeError("FARO_REQUESTS_PER_MINUTE fora da faixa")
    db = Storage(db_path or os.getenv("FARO_DB_PATH", str(ROOT / ".local" / "faro.sqlite3")))
    dns_enabled = os.getenv("FARO_DNS_ENABLED", "0").lower() in {"1", "true", "yes"}
    dns_collector = PassiveDNSCollector(os.getenv("FARO_DNS_RESOLVER", "1.1.1.1")) if dns_enabled else None
    rdap_enabled = os.getenv("FARO_RDAP_ENABLED", "0").lower() in {"1", "true", "yes"}
    ct_enabled = os.getenv("FARO_CT_ENABLED", "0").lower() in {"1", "true", "yes"}
    rdap_collector = RDAPCollector() if rdap_enabled else None
    ct_collector = CertificateTransparencyCollector() if ct_enabled else None
    ti_collector = configured_snapshot()
    app = FastAPI(title="FARO — MVP OSINT & Antiphishing", version="0.6.0", description="Motor lexical offline, HTML opcional fornecido pelo usuario, grafo de indicadores sem atribuicao de pessoas.")

    def require_key(x_faro_api_key: str | None = Header(default=None)) -> Principal:
        principal = registry.resolve(x_faro_api_key)
        if principal is None:
            raise HTTPException(status_code=401, detail="Credencial de API ausente ou invalida")
        if not db.consume_request_quota(principal.tenant_id, requests_per_minute):
            raise HTTPException(status_code=429, detail="Limite de requisicoes por minuto excedido", headers={"Retry-After": "60"})
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
        return {"status": "ok", "version": "0.6.0", "remote_fetch_enabled": False, "passive_dns_enabled": dns_enabled, "rdap_enabled": rdap_enabled, "ct_enabled": ct_enabled, "live_tls_enabled": False, "reputation_snapshot_enabled": ti_collector is not None}

    @app.post("/v1/analyses", response_model=AnalysisResult, status_code=201, tags=["analysis"])
    def analyze(request: AnalysisRequest, principal: Principal = Depends(require_analyst)):
        try:
            target = normalize_url(request.url)
        except URLValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not db.consume_analysis_quota(principal.tenant_id, principal.hourly_quota):
            raise HTTPException(status_code=429, detail="Quota horaria de analises excedida")
        assessment, evidence, extras = evaluate(target, request.observed_html)
        passive_dns = dns_collector.collect(target.hostname) if dns_collector else DNSObservation(
            status="disabled", resolver="not_configured", note="DNS passivo desabilitado na configuracao.")
        if passive_dns.records:
            evidence.append(Evidence(id="ev-dns-001", code="passive_dns_observation", title="DNS passivo observado",
                detail="Respostas DNS publicas consultadas para o dominio; nao comprovam participacao em fraude.",
                source="public_recursive_dns", impact=0, confidence="medium"))
        rdap = rdap_collector.collect(target.registrable_domain) if rdap_collector else RDAPObservation(
            status="disabled", source="registry_rdap", note="Consulta RDAP desativada pela configuracao.")
        ct = ct_collector.collect(target.registrable_domain) if ct_collector else CTObservation(
            status="disabled", source="crt_sh_ct_index", note="Consulta CT desativada pela configuracao.")
        if rdap.status == "observed":
            evidence.append(Evidence(id="ev-rdap-001", code="rdap_registry_observation", title="Registro RDAP consultado",
                detail="Metadados publicos do registro do dominio consultados; nao identificam autores de fraude.",
                source="registry_rdap", impact=0, confidence="medium"))
        if ct.status in {"observed", "partial"} and ct.certificates_matched:
            evidence.append(Evidence(id="ev-ct-001", code="ct_historical_observation", title="Certificados historicos observados",
                detail="Registros historicos de transparencia de certificados relacionados ao dominio; nao validam TLS atual.",
                source="crt_sh_ct_index", impact=0, confidence="medium"))
        intel = ti_collector.check(target) if ti_collector else ThreatIntelObservation(
            status="disabled", source="local_licensed_snapshot", note="Feed de reputacao local nao configurado.")
        if intel.matches:
            # Um hostname em feed e sinal contextual; URL exata e correspondencia mais forte.
            for idx, match in enumerate(intel.matches):
                evidence.append(Evidence(id=f"ev-ti-{idx+1:03d}", code="reputation_feed_match",
                    title="Indicador reportado por fonte de reputacao",
                    detail=(f"Correspondencia {match.indicator_type} ({match.category}) reportada por {match.source} "
                            f"em {match.observed_at}, valida ate {match.expires_at}. Nao comprova atividade atual."),
                    source=match.source, impact=0, confidence="medium"))
            strongest = 80 if any(m.indicator_type == "url" for m in intel.matches) else 55
            assessment.score = max(assessment.score, strongest)
            assessment.level = ("critical" if assessment.score >= 80 else "high" if assessment.score >= 60
                                else "moderate" if assessment.score >= 35 else "low")
            assessment.confidence = "medium"
            assessment.coverage = ("lexical_html_and_feed" if request.observed_html is not None
                                   else "lexical_and_feed")
            assessment.recommendation = ("Indicador reportado em fonte autorizada; evite fornecer dados "
                "ou efetuar pagamentos e confirme a legitimidade por canal oficial independente.")
        analysis_id = str(uuid.uuid4())
        result = AnalysisResult(
            analysis_id=analysis_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            normalized_url=target.url,
            hostname=target.hostname,
            registrable_domain=target.registrable_domain,
            assessment=assessment,
            evidence=evidence,
            passive_dns=passive_dns,
            rdap=rdap,
            certificate_transparency=ct,
            threat_intel=intel,
            limitations=[
                "Nao ha navegacao ao site investigado ou inspecao TLS ao vivo. DNS, RDAP, CT e feeds locais sao opcionais.",
                "Feeds sao snapshots locais autorizados e podem estar incompletos ou desatualizados; sem match nao significa site seguro.",
                "HTML opcional e fornecido pelo solicitante e nao e uma evidencia independente.",
                "A pontuacao e heuristica, nao uma probabilidade calibrada ou confirmacao de fraude.",
                "O grafo representa indicadores observados/hipoteses, nao responsaveis identificados.",
            ],
        )
        graph = build_graph(analysis_id, target.url, target.hostname, target.registrable_domain, [e.model_dump() for e in evidence], extras, passive_dns, rdap, intel)
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

    # Investigation cases are strictly tenant-scoped. They group existing scans;
    # neither the case label nor a human review establishes identity or guilt.
    @app.post("/v1/cases", status_code=201, tags=["cases"])
    def create_case(request: CaseCreateRequest, principal: Principal = Depends(require_analyst)):
        case_id = str(uuid.uuid4())
        try:
            return db.create_case(case_id, request.title, [str(a) for a in request.analysis_ids],
                                  principal.tenant_id, principal.actor_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/v1/cases", tags=["cases"])
    def list_cases(limit: int = Query(default=50, ge=1, le=100), principal: Principal = Depends(require_key)):
        return db.list_cases(principal.tenant_id, limit)

    @app.get("/v1/cases/{case_id}", tags=["cases"])
    def get_case(case_id: uuid.UUID, principal: Principal = Depends(require_key)):
        record = db.get_case(str(case_id), principal.tenant_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Caso inexistente")
        return record

    @app.post("/v1/cases/{case_id}/analyses", tags=["cases"])
    def link_analysis(case_id: uuid.UUID, request: CaseLinkRequest, principal: Principal = Depends(require_analyst)):
        try:
            return db.add_case_analysis(str(case_id), str(request.analysis_id), principal.tenant_id, principal.actor_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/cases/{case_id}/reviews", status_code=201, tags=["cases"])
    def submit_review(case_id: uuid.UUID, request: CaseReviewRequest, principal: Principal = Depends(require_analyst)):
        try:
            return db.review_case(str(case_id), str(uuid.uuid4()), request.decision, request.rationale,
                                  principal.tenant_id, principal.actor_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.patch("/v1/cases/{case_id}/status", tags=["cases"])
    def change_case_status(case_id: uuid.UUID, request: CaseStatusRequest, principal: Principal = Depends(require_admin)):
        try:
            return db.update_case_status(str(case_id), request.status, request.expected_version,
                                         principal.tenant_id, principal.actor_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    def case_records(case_id: uuid.UUID, principal: Principal):
        saved = db.get_case_records(str(case_id), principal.tenant_id)
        if saved is None:
            raise HTTPException(status_code=404, detail="Caso inexistente")
        return saved

    @app.get("/v1/cases/{case_id}/graph", tags=["cases", "graph"])
    def get_case_graph(case_id: uuid.UUID, principal: Principal = Depends(require_key)):
        _, records = case_records(case_id, principal)
        return aggregate_case_graph(str(case_id), records)

    @app.get("/v1/cases/{case_id}/dossier", tags=["cases"])
    def get_case_dossier(case_id: uuid.UUID, principal: Principal = Depends(require_key)):
        record, records = case_records(case_id, principal)
        dossier = build_dossier(record, records)
        return JSONResponse(content=dossier, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.get("/v1/audit", dependencies=[Depends(require_admin)], tags=["operations"])
    def get_audit(limit: int = Query(default=100, ge=1, le=500), principal: Principal = Depends(require_admin)):
        return {"events": db.list_audit(principal.tenant_id, limit=limit)}

    ui_path = ROOT / "apps" / "consumer-web"
    if ui_path.is_dir():
        app.mount("/", StaticFiles(directory=ui_path, html=True), name="web")
    return app


# Variavel para execucao com `uvicorn faro_api.main:app`.
# Testes usam create_app(db_path=..., api_key=...) para isolamento.
if os.getenv("FARO_API_KEY") or os.getenv("FARO_TENANTS_JSON"):
    app = create_app()
else:
    app = None
