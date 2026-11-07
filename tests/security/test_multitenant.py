import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from faro_api.main import create_app


KEYS = [
    {"tenant_id": "acme", "hourly_quota": 2, "keys": [
        {"key_id": "acme-1", "actor_id": "ana", "role": "analyst", "key": "acme-key-000000000001"},
        {"key_id": "acme-2", "actor_id": "leo", "role": "reader", "key": "acme-key-000000000002"},
        {"key_id": "acme-3", "actor_id": "bia", "role": "admin", "key": "acme-key-000000000003"},
    ]},
    {"tenant_id": "beta", "hourly_quota": 10, "keys": [
        {"key_id": "beta-1", "actor_id": "joao", "role": "admin", "key": "beta-key-000000000001"},
    ]},
]


def headers(key):
    return {"X-Faro-Api-Key": key}


@pytest.fixture
def multi(tmp_path):
    db_path = str(tmp_path / 'multi.sqlite3')
    with TestClient(create_app(db_path=db_path, api_key=None, tenants_json=json.dumps(KEYS))) as c:
        yield c, db_path


def test_tenant_isolation_and_role_enforcement(multi):
    client, _ = multi
    analyst = headers(KEYS[0]['keys'][0]['key'])
    reader = headers(KEYS[0]['keys'][1]['key'])
    admin = headers(KEYS[0]['keys'][2]['key'])
    beta = headers(KEYS[1]['keys'][0]['key'])
    assert client.post('/v1/analyses', headers=reader, json={'url': 'example.com'}).status_code == 403
    analysis = client.post('/v1/analyses', headers=analyst, json={'url': 'example.com'})
    assert analysis.status_code == 201
    identifier = analysis.json()['analysis_id']
    assert len(client.get('/v1/analyses', headers=reader).json()) == 1
    assert client.get(f'/v1/analyses/{identifier}', headers=beta).status_code == 404
    assert client.get(f'/v1/analyses/{identifier}/graph', headers=beta).status_code == 404
    assert client.get(f'/v1/analyses/{identifier}/evidence', headers=beta).status_code == 404
    assert client.get('/v1/analyses', headers=beta).json() == []
    assert client.get('/v1/audit', headers=reader).status_code == 403
    assert client.get('/v1/audit', headers=analyst).status_code == 403
    events = client.get('/v1/audit', headers=admin).json()['events']
    assert len(events) == 1
    assert events[0]['actor_id'] == 'ana'
    assert events[0]['object_id'] == identifier
    assert client.get('/v1/audit', headers=beta).json()['events'] == []


def test_quota_is_per_tenant_and_invalid_requests_do_not_consume(multi):
    client, _ = multi
    a = headers(KEYS[0]['keys'][0]['key'])
    b = headers(KEYS[1]['keys'][0]['key'])
    assert client.post('/v1/analyses', headers=a, json={'url': 'http://127.0.0.1'}).status_code == 422
    assert client.post('/v1/analyses', headers=a, json={'url': 'example.com'}).status_code == 201
    assert client.post('/v1/analyses', headers=a, json={'url': 'foo.example.com'}).status_code == 201
    assert client.post('/v1/analyses', headers=a, json={'url': 'bar.example.com'}).status_code == 429
    assert client.post('/v1/analyses', headers=b, json={'url': 'bar.example.com'}).status_code == 201


def test_secrets_not_stored_or_returned(multi):
    client, path = multi
    secret = KEYS[0]['keys'][0]['key']
    result = client.post('/v1/analyses', headers=headers(secret), json={'url': 'example.com/reset/a1b2c3'})
    assert result.status_code == 201
    with sqlite3.connect(path) as conn:
        dump = '\n'.join(str(row) for row in conn.iterdump())
    assert secret not in dump
    assert 'a1b2c3' not in dump
    assert 'a1b2c3' not in result.text


def test_bad_tenant_config_and_duplicate_keys(tmp_path):
    cfg = json.loads(json.dumps(KEYS))
    cfg[1]['keys'][0]['key'] = cfg[0]['keys'][0]['key']
    with pytest.raises(RuntimeError):
        create_app(str(tmp_path/'x.db'), api_key=None, tenants_json=json.dumps(cfg))
