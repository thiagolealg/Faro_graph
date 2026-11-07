import json
from fastapi.testclient import TestClient
from faro_api.main import create_app


CONFIG = [
    {"tenant_id": "north", "hourly_quota": 30, "keys": [
        {"key_id": "one", "actor_id": "analyst-n", "role": "analyst", "key": "key-north-analyst-000001"},
        {"key_id": "two", "actor_id": "reader-n", "role": "reader", "key": "key-north-reader-000002"},
        {"key_id": "three", "actor_id": "admin-n", "role": "admin", "key": "key-north-admin-000003"},
    ]},
    {"tenant_id": "south", "hourly_quota": 30, "keys": [
        {"key_id": "four", "actor_id": "admin-s", "role": "admin", "key": "key-south-admin-000004"},
    ]},
]


def h(tenant, idx):
    return {"X-Faro-Api-Key": CONFIG[tenant]['keys'][idx]['key']}


def test_cases_tenant_isolation_roles_and_no_secret_leakage(tmp_path):
    path = tmp_path / 'isolated.sqlite3'
    with TestClient(create_app(db_path=str(path), api_key=None, tenants_json=json.dumps(CONFIG))) as c:
        north, reader, admin, south = h(0, 0), h(0, 1), h(0, 2), h(1, 0)
        first = c.post('/v1/analyses', headers=north, json={'url': 'example.com/token/sensitive-secret-value'}).json()['analysis_id']
        other = c.post('/v1/analyses', headers=south, json={'url': 'other.example.com'}).json()['analysis_id']
        assert c.post('/v1/cases', headers=reader, json={'title': 'Triagem de dominios'}).status_code == 403
        assert c.post('/v1/cases', headers=north, json={
            'title': 'Caso compartilhado', 'analysis_ids': [other]}).status_code == 404
        response = c.post('/v1/cases', headers=north, json={'title': 'Investigacao local', 'analysis_ids': [first]})
        assert response.status_code == 201
        case_id = response.json()['id']
        assert c.post(f'/v1/cases/{case_id}/analyses', headers=north, json={'analysis_id': other}).status_code == 404
        for suffix in ['', '/graph', '/dossier']:
            assert c.get(f'/v1/cases/{case_id}{suffix}', headers=south).status_code == 404
        assert c.patch(f'/v1/cases/{case_id}/status', headers=south,
                       json={'status':'closed','expected_version':1}).status_code == 404
        assert c.post(f'/v1/cases/{case_id}/reviews', headers=south, json={
            'decision':'suspected', 'rationale':'Dados avaliados pelo investigador habilitado.'}).status_code == 404
        assert c.get('/v1/cases', headers=south).json() == []
        assert c.get(f'/v1/cases/{case_id}', headers=reader).status_code == 200
        assert c.post(f'/v1/cases/{case_id}/reviews', headers=reader, json={
            'decision':'suspected', 'rationale':'Dados avaliados pelo investigador habilitado.'}).status_code == 403
        assert c.patch(f'/v1/cases/{case_id}/status', headers=north,
                       json={'status':'closed','expected_version':1}).status_code == 403
        assert c.patch(f'/v1/cases/{case_id}/status', headers=admin,
                       json={'status':'closed','expected_version':1}).status_code == 200
        dossier = c.get(f'/v1/cases/{case_id}/dossier', headers=reader).text
        assert 'sensitive-secret-value' not in dossier
        assert CONFIG[0]['keys'][0]['key'] not in path.read_bytes().decode('utf8',errors='ignore')
        assert other not in dossier
        assert all(not event['action'].startswith('case.') for event in c.get('/v1/audit',headers=south).json()['events'])


def test_case_survives_restart_and_data_remains_tenant_scoped(tmp_path):
    db = str(tmp_path / 'restart.db')
    north, south = h(0, 0), h(1, 0)
    with TestClient(create_app(db_path=db, api_key=None, tenants_json=json.dumps(CONFIG))) as c:
        analysis_id = c.post('/v1/analyses', headers=north, json={'url': 'examplenew.com'}).json()['analysis_id']
        case_id = c.post('/v1/cases', headers=north,
                         json={'title': 'Caso persistente', 'analysis_ids': [analysis_id]}).json()['id']
    with TestClient(create_app(db_path=db, api_key=None, tenants_json=json.dumps(CONFIG))) as c:
        assert c.get(f'/v1/cases/{case_id}', headers=north).json()['analysis_ids'] == [analysis_id]
        assert c.get(f'/v1/cases/{case_id}/dossier', headers=north).status_code == 200
        assert c.get(f'/v1/cases/{case_id}/dossier', headers=south).status_code == 404
