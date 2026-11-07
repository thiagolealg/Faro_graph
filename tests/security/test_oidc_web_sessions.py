"""Browser auth: session cookie, PKCE state, CSRF, RBAC and tenant isolation."""
import base64
import hashlib
import json
import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from faro_api.auth import Principal
from faro_api.main import create_app
from faro_api.web_auth import (CSRF_COOKIE, OIDCConfig, OIDCService,
                               SESSION_COOKIE, STATE_COOKIE)


CONFIG = {
    'issuer': 'https://login.example.org/realms/faro',
    'authorize_url': 'https://login.example.org/realms/faro/protocol/authorize',
    'token_url': 'https://login.example.org/realms/faro/protocol/token',
    'jwks_url': 'https://login.example.org/realms/faro/protocol/jwks',
    'client_id': 'faro-web',
    'redirect_uri': 'https://faro.example/v1/auth/callback',
    'ui_origin': 'https://faro.example',
}
USERS = [
    {'subject': 'subject-admin-1', 'tenant_id': 'org-one', 'actor_id': 'alice',
     'role': 'admin', 'hourly_quota': 15},
    {'subject': 'subject-reader-2', 'tenant_id': 'org-two', 'actor_id': 'bruno',
     'role': 'reader', 'hourly_quota': 15},
]


@pytest.fixture
def session_env(tmp_path, monkeypatch):
    monkeypatch.setenv('FARO_OIDC_CONFIG', json.dumps(CONFIG))
    monkeypatch.setenv('FARO_OIDC_USERS_JSON', json.dumps(USERS))
    monkeypatch.delenv('FARO_TENANTS_JSON', raising=False)
    monkeypatch.delenv('FARO_API_KEY', raising=False)
    monkeypatch.setattr(OIDCService, '_token', lambda self, code, verifier: 'mocked-id-token')
    monkeypatch.setattr(OIDCService, '_validate', lambda self, token, nonce: self.config.users['subject-admin-1'])
    path = str(tmp_path/'oidc.db')
    app = create_app(db_path=path, api_key=None, tenants_json=None)
    with TestClient(app, base_url='https://faro.example') as client:
        yield client, path


def login(client):
    resp = client.get('/v1/auth/login', follow_redirects=False)
    assert resp.status_code == 302
    assert 'HttpOnly' in resp.headers['set-cookie'] and 'secure' in resp.headers['set-cookie'].lower()
    query = parse_qs(urlsplit(resp.headers['location']).query)
    assert query['code_challenge_method'] == ['S256']
    assert query['response_type'] == ['code']
    assert query['scope'] == ['openid']
    assert query['redirect_uri'] == [CONFIG['redirect_uri']]
    assert 'code_verifier' not in query
    assert client.cookies.get(STATE_COOKIE) == query['state'][0]
    callback = client.get('/v1/auth/callback', params={'state': query['state'][0], 'code': 'once'},
                          follow_redirects=False)
    assert callback.status_code == 303
    assert callback.headers['location'] == '/'
    assert client.cookies.get(SESSION_COOKIE)
    assert client.cookies.get(CSRF_COOKIE)
    return query


def test_cookie_flags_allowlisted_user_and_nonsecret_database(session_env):
    client, path = session_env
    login(client)
    response = client.get('/v1/auth/session')
    assert response.status_code == 200
    payload = response.json()
    assert payload['tenant_id'] == 'org-one' and payload['role'] == 'admin'
    assert payload['csrf_token'] == client.cookies.get(CSRF_COOKIE)
    assert 'no-store' in response.headers.get('cache-control')
    assert 'nosniff' == response.headers['x-content-type-options']
    assert "frame-ancestors 'none'" in response.headers['content-security-policy']
    with sqlite3.connect(path) as con:
        dump = '\n'.join(str(r) for r in con.iterdump())
    assert client.cookies.get(SESSION_COOKIE) not in dump
    assert client.cookies.get(CSRF_COOKIE) not in dump


def test_oidc_requires_csrf_and_exact_origin(session_env):
    client, _ = session_env
    login(client)
    assert client.post('/v1/analyses', json={'url':'example.com'}).status_code == 403
    csrf = client.get('/v1/auth/session').json()['csrf_token']
    assert client.post('/v1/analyses', headers={'Origin':'https://attacker.example', 'X-Faro-CSRF':csrf},
                       json={'url':'example.com'}).status_code == 403
    assert client.post('/v1/analyses', headers={'Origin':CONFIG['ui_origin'], 'X-Faro-CSRF':'bad'},
                       json={'url':'example.com'}).status_code == 403
    ok = client.post('/v1/analyses', headers={'Origin':CONFIG['ui_origin'], 'X-Faro-CSRF':csrf},
                     json={'url':'example.com'})
    assert ok.status_code == 201, ok.text
    assert client.get('/v1/analyses').status_code == 200


def test_logout_revokes_and_cannot_be_get(session_env):
    client, _ = session_env
    login(client)
    csrf = client.get('/v1/auth/session').json()['csrf_token']
    assert client.get('/v1/auth/logout').status_code in (404, 405)
    assert client.post('/v1/auth/logout',headers={'Origin':CONFIG['ui_origin'],'X-Faro-CSRF':'bad'}).status_code == 403
    assert client.post('/v1/auth/logout', headers={'Origin':CONFIG['ui_origin'],'X-Faro-CSRF':csrf}).status_code == 200
    assert client.get('/v1/auth/session').status_code == 401
    assert client.get('/v1/analyses').status_code == 401


def test_state_cookie_binding_and_replay(session_env):
    client, _ = session_env
    first = client.get('/v1/auth/login', follow_redirects=False)
    state = parse_qs(urlsplit(first.headers['location']).query)['state'][0]
    assert client.get('/v1/auth/callback', params={'state': 'invalid-state-123456','code':'a'}).status_code == 401
    assert client.get('/v1/auth/callback', params={'state':state,'code':'ok'},follow_redirects=False).status_code == 303
    assert client.get('/v1/auth/callback',params={'state':state,'code':'ok'},follow_redirects=False).status_code == 401


def test_read_only_tenant_and_key_header_priority(session_env, monkeypatch):
    client, _ = session_env
    login(client)
    csrf = client.get('/v1/auth/session').json()['csrf_token']
    assert client.get('/v1/analyses',headers={'X-Faro-Api-Key':'invalid'}).status_code == 401
    assert client.post('/v1/cases',json={'title':'Teste caso isolado', 'analysis_ids':[]},
                       headers={'Origin':CONFIG['ui_origin'],'X-Faro-CSRF':csrf}).status_code == 201
    monkeypatch.setattr(OIDCService, '_validate', lambda self, token, nonce: self.config.users['subject-reader-2'])
    client.post('/v1/auth/logout', headers={'Origin':CONFIG['ui_origin'],'X-Faro-CSRF':csrf})
    login(client)
    assert client.get('/v1/cases').json() == []
    csrf = client.get('/v1/auth/session').json()['csrf_token']
    assert client.post('/v1/analyses',json={'url':'example.org'},
                       headers={'Origin':CONFIG['ui_origin'],'X-Faro-CSRF':csrf}).status_code == 403
    assert client.get('/v1/audit').status_code == 403


def test_local_api_key_mode_unchanged(tmp_path, monkeypatch):
    monkeypatch.delenv('FARO_OIDC_CONFIG', raising=False)
    monkeypatch.delenv('FARO_OIDC_USERS_JSON', raising=False)
    app = create_app(db_path=str(tmp_path/'legacy.db'), api_key='legacy-key')
    with TestClient(app) as c:
        assert c.get('/v1/auth/config').json()['mode'] == 'api_key_local'
        assert c.get('/v1/auth/login').status_code == 404
        assert c.get('/v1/analyses',headers={'X-Faro-Api-Key':'legacy-key'}).status_code == 200
        assert c.get('/v1/analyses').status_code == 401


@pytest.mark.parametrize('field,value', [
    ('redirect_uri','http://faro.example/v1/auth/callback'),
    ('redirect_uri','https://attacker.example/v1/auth/callback'),
    ('token_url','http://login.example.org/token'),
    ('jwks_url','https://127.0.0.1/test#fragment'),
    ('ui_origin','https://faro.example/extra'),
])
def test_invalid_provider_config_rejected(field,value,monkeypatch):
    config = dict(CONFIG); config[field] = value
    with pytest.raises(RuntimeError):
        OIDCConfig.from_env(json.dumps(config), json.dumps(USERS))


def test_user_allowlist_is_mandatory():
    with pytest.raises(RuntimeError):
        OIDCConfig.from_env(json.dumps(CONFIG), '[]')


def test_duplicate_subject_cannot_override_tenant():
    with pytest.raises(RuntimeError):
        OIDCConfig.from_env(json.dumps(CONFIG), json.dumps(USERS + [USERS[0]]))


def test_oidc_pkce_correct_challenge(session_env):
    client, path = session_env
    resp = client.get('/v1/auth/login',follow_redirects=False)
    q = parse_qs(urlsplit(resp.headers['location']).query)
    with sqlite3.connect(path) as conn:
        row=conn.execute('SELECT verifier FROM oidc_pending').fetchone()
    expected=base64.urlsafe_b64encode(hashlib.sha256(row[0].encode()).digest()).rstrip(b'=').decode()
    assert q['code_challenge'][0] == expected


def test_revocation_on_changed_user_allowlist(session_env, monkeypatch):
    client, path = session_env
    login(client)
    sid = client.cookies.get(SESSION_COOKIE)
    # Restart with the same SQLite DB but without the previously authorized identity.
    users = [USERS[1]]
    monkeypatch.setenv('FARO_OIDC_USERS_JSON', json.dumps(users))
    app = create_app(db_path=path, api_key=None, tenants_json=None)
    with TestClient(app, base_url='https://faro.example') as another:
        another.cookies.set(SESSION_COOKIE, sid, domain='faro.example', path='/')
        assert another.get('/v1/analyses').status_code == 401
    assert client.get('/v1/analyses').status_code == 401
