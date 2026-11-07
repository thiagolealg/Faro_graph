import pytest
from faro_api.main import create_app
from faro_api.url_security import normalize_url, URLValidationError


def test_key_is_mandatory(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(db_path=str(tmp_path / "db.sqlite"), api_key="")


def test_html_is_not_persisted(client, auth):
    secret = "CUSTOMER_PASSWORD_NEVER_STORE_7183"
    r = client.post("/v1/analyses", headers=auth, json={"url":"https://example.com", "observed_html":f'<input type="password" value="{secret}">'})
    assert r.status_code == 201
    assert secret not in str(r.json())
    result = client.get(f"/v1/analyses/{r.json()['analysis_id']}", headers=auth)
    assert secret not in result.text


def test_no_credential_url(client, auth):
    r = client.post("/v1/analyses", headers=auth, json={"url":"https://root:secret@example.com"})
    assert r.status_code == 422


def test_unsupported_schemes():
    for url in ("file:///etc/passwd", "gopher://example.com", "javascript://example.com", "data://example.com"):
        with pytest.raises(URLValidationError):
            normalize_url(url)
