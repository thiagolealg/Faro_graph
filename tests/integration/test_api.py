import uuid


def test_health_without_key(client):
    assert client.get("/healthz").json()["remote_fetch_enabled"] is False


def test_unauthorized(client):
    assert client.post("/v1/analyses", json={"url": "https://example.com"}).status_code == 401
    assert client.get("/v1/analyses").status_code == 401


def test_full_flow_persists_and_exposes_graph(client, auth):
    created = client.post("/v1/analyses", headers=auth, json={
        "url": "https://paypal-verificacao.example/?secret=must-not-be-logged",
        "observed_html": '<form action="https://forms.example/capture"><input type="password" name="password"></form>',
    })
    assert created.status_code == 201, created.text
    data = created.json()
    identifier = data["analysis_id"]
    assert uuid.UUID(identifier)
    assert "must-not-be-logged" not in str(data)
    assert data["status"] == "completed"
    assert data["assessment"]["level"] in ("high", "critical")
    assert data["assessment"]["coverage"] == "lexical_and_submitted_html"
    assert all("<form" not in str(item) for item in data["evidence"])
    assert client.get(f"/v1/analyses/{identifier}", headers=auth).json() == data
    evidence = client.get(f"/v1/analyses/{identifier}/evidence", headers=auth).json()
    assert evidence["evidence"] == data["evidence"]
    graph = client.get(f"/v1/analyses/{identifier}/graph", headers=auth).json()
    assert any(e["relationship"] == "resembles_brand" and e["certainty"] == "hypothesis" for e in graph["edges"])
    assert any(e["relationship"] == "form_target_in_submitted_html" for e in graph["edges"])
    assert len(client.get("/v1/analyses", headers=auth).json()) == 1


def test_bad_url_and_missing(client, auth):
    assert client.post("/v1/analyses", headers=auth, json={"url": "http://127.0.0.1"}).status_code == 422
    assert client.get(f"/v1/analyses/{uuid.uuid4()}", headers=auth).status_code == 404
    assert client.get("/v1/analyses?limit=101", headers=auth).status_code == 422


def test_ui_available(client):
    result = client.get("/")
    assert result.status_code == 200
    assert "FARO" in result.text
