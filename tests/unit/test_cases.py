import hashlib

from faro_api.case_schemas import CaseCreateRequest, CaseReviewRequest
from faro_api.cases import aggregate_case_graph, build_dossier, canonical_bytes
from pydantic import ValidationError
import pytest


def _record(analysis_id, host, extra=None):
    nodes = [
        {"id": "domain:" + host, "kind": "hostname", "label": host, "status": "observed"},
        {"id": "ip:1.1.1.1", "kind": "ip_address", "label": "1.1.1.1", "status": "observed"},
        {"id": "feed:generic", "kind": "threat_intel_source", "label": "generic", "status": "reference"},
    ]
    nodes += extra or []
    result = {
        "analysis_id": analysis_id, "created_at": "2026-11-07T12:00:00+00:00",
        "normalized_url": "https://" + host + "/", "hostname": host,
        "assessment": {"score": 5}, "evidence": [], "limitations": [],
    }
    return result, {"nodes": nodes, "edges": []}


def _case():
    return {"id": "case-1", "tenant_id": "alpha", "title": "Investigacao de teste", "status": "open",
            "created_by": "analyst", "version": 1, "created_at": "2026-11-07", "updated_at": "2026-11-07",
            "analysis_ids": ["a", "b"], "reviews": []}


def test_graph_shares_only_technical_indicators():
    result = aggregate_case_graph("case-1", [_record("a", "one.example"), _record("b", "two.example")])
    assert len(result["shared_indicators"]) == 1
    found = result["shared_indicators"][0]
    assert found["node_id"] == "ip:1.1.1.1"
    assert found["analysis_ids"] == ["a", "b"]
    assert found["interpretation"] == "weak_shared_infrastructure_only"
    assert not any(item["node_id"].startswith("feed:") for item in result["shared_indicators"])
    assert "nao comprovam" in result["notice"]


def test_dossier_hash_is_reproducible_and_tamper_evident():
    case = _case()
    records = [_record("a", "one.example"), _record("b", "two.example")]
    original = build_dossier(case, records)
    duplicate = build_dossier(case, records)
    assert original == duplicate
    assert original["integrity"]["digest"] == hashlib.sha256(canonical_bytes(original["dossier"])).hexdigest()
    assert original["integrity"]["digitally_signed"] is False
    original["dossier"]["case"]["title"] = "Alterado"
    assert hashlib.sha256(canonical_bytes(original["dossier"])).hexdigest() != original["integrity"]["digest"]


def test_graph_empty_case_and_unique_node_deduplication():
    assert aggregate_case_graph("case-1", [])["nodes"] == []
    graph = aggregate_case_graph("case-1", [_record("a", "one.example"), _record("b", "one.example")])
    assert len([x for x in graph["nodes"] if x["id"] == "domain:one.example"]) == 1
    assert any(x["interpretation"] == "same_observed_indicator_only" for x in graph["shared_indicators"])


@pytest.mark.parametrize("title", ["abc", "https://foo.com", "Cliente@exemplo", "Erro?token=x", "1234\nxxxx"])
def test_case_rejects_sensitive_or_invalid_titles(title):
    with pytest.raises(ValidationError):
        CaseCreateRequest(title=title)


@pytest.mark.parametrize("rationale", ["breve", "Token: abcdefghijklmnopqrst e identificadores", "Acesso https://x.example/ abc", "Pessoa usuario@exemplo.org foi informada"])
def test_review_rejects_sensitive_content(rationale):
    with pytest.raises(ValidationError):
        CaseReviewRequest(decision="suspected", rationale=rationale)


def test_duplicate_initial_analysis_ids_rejected():
    from uuid import uuid4
    unique_id = uuid4()
    with pytest.raises(ValidationError):
        CaseCreateRequest(title="Investigacao nova", analysis_ids=[unique_id, unique_id])
