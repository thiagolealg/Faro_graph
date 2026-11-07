import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from faro_api.main import create_app


def setup_feed(tmp_path, monkeypatch, kind="url"):
    now = datetime.now(timezone.utc)
    doc = {"type": kind, "indicator": "https://example.com/login" if kind == "url" else "example.com",
           "source": "licensed_mock", "category": "phishing", "observed_at": (now - timedelta(days=1)).isoformat(),
           "expires_at": (now + timedelta(days=1)).isoformat()}
    p = tmp_path / "trusted-feed.jsonl"
    p.write_text(json.dumps(doc))
    monkeypatch.setenv("FARO_TI_ENABLED", "1")
    monkeypatch.setenv("FARO_TI_LICENSE_ACK", "1")
    monkeypatch.setenv("FARO_TI_PATH", str(p))
    return p


def test_opt_in_exact_match_and_graph_persistence(tmp_path, monkeypatch):
    setup_feed(tmp_path, monkeypatch)
    with TestClient(create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")) as client:
        headers = {"X-Faro-Api-Key": "test-key"}
        assert client.get("/healthz").json()["reputation_snapshot_enabled"]
        response = client.post("/v1/analyses", headers=headers, json={"url": "https://example.com/login"})
        assert response.status_code == 201
        data = response.json()
        assert data["assessment"]["score"] >= 80
        assert data["assessment"]["level"] == "critical"
        assert data["assessment"]["classification"] == "suspicion_only"
        assert data["assessment"]["coverage"] == "lexical_and_feed"
        assert data["threat_intel"]["status"] == "matched"
        assert data["threat_intel"]["matches"][0]["source"] == "licensed_mock"
        assert any(ev["code"] == "reputation_feed_match" and ev["impact"] == 0 for ev in data["evidence"])
        graph = client.get(f"/v1/analyses/{data['analysis_id']}/graph", headers=headers).json()
        assert any(e["relationship"] == "reported_in_reputation_snapshot" and e["certainty"] == "observed" for e in graph["edges"])
        assert client.get(f"/v1/analyses/{data['analysis_id']}", headers=headers).json()["threat_intel"] == data["threat_intel"]


def test_no_match_never_means_safe(tmp_path, monkeypatch):
    setup_feed(tmp_path, monkeypatch)
    with TestClient(create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")) as client:
        d = client.post("/v1/analyses", headers={"X-Faro-Api-Key": "test-key"},
                        json={"url": "https://example.com/other"}).json()
        assert d["threat_intel"]["status"] == "no_match"
        assert d["assessment"]["level"] == "inconclusive"
        assert "nao representa garantia" in d["threat_intel"]["note"]


def test_hostname_match_moderate_not_critical(tmp_path, monkeypatch):
    setup_feed(tmp_path, monkeypatch, "hostname")
    with TestClient(create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")) as client:
        d = client.post("/v1/analyses", headers={"X-Faro-Api-Key": "test-key"},
                        json={"url": "https://example.com/any-path"}).json()
        assert d["assessment"]["level"] == "moderate"
        assert d["assessment"]["score"] == 55


def test_disabled_does_not_read_feed(tmp_path, monkeypatch):
    monkeypatch.delenv("FARO_TI_ENABLED", raising=False)
    monkeypatch.setenv("FARO_TI_PATH", "/missing/feed.jsonl")
    with TestClient(create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")) as client:
        d = client.post("/v1/analyses", headers={"X-Faro-Api-Key": "test-key"},
                        json={"url": "https://example.com/login"}).json()
        assert d["threat_intel"]["status"] == "disabled"


def test_requires_explicit_license_and_absolute_path(tmp_path, monkeypatch):
    setup_feed(tmp_path, monkeypatch)
    monkeypatch.delenv("FARO_TI_LICENSE_ACK", raising=False)
    with pytest.raises(RuntimeError, match="LICENSE_ACK"):
        create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")
    monkeypatch.setenv("FARO_TI_LICENSE_ACK", "1")
    monkeypatch.setenv("FARO_TI_PATH", "relative-feed.jsonl")
    with pytest.raises(RuntimeError, match="absoluto"):
        create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")


def test_invalid_feed_blocks_startup_instead_of_silent_empty_result(tmp_path, monkeypatch):
    p = setup_feed(tmp_path, monkeypatch)
    p.write_text('{"invalid": true}\n')
    with pytest.raises(RuntimeError, match="Falha ao carregar"):
        create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")


def test_bad_feature_flag_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("FARO_TI_ENABLED", "maybe")
    with pytest.raises(RuntimeError, match="FARO_TI_ENABLED"):
        create_app(db_path=str(tmp_path / "db.sqlite"), api_key="test-key")
