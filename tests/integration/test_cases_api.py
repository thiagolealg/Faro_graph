from uuid import uuid4
import hashlib
import json

from faro_api.cases import canonical_bytes


def _analysis(client, auth, url):
    response = client.post('/v1/analyses', headers=auth, json={'url': url})
    assert response.status_code == 201, response.text
    return response.json()['analysis_id']


def _case(client, auth, ids=None):
    response = client.post('/v1/cases', headers=auth, json={'title': 'Investigacao inicial de dominios', 'analysis_ids': ids or []})
    assert response.status_code == 201, response.text
    return response.json()


def test_full_investigative_case_lifecycle(client, auth):
    first = _analysis(client, auth, 'sub.example.com/login')
    second = _analysis(client, auth, 'other.example.com/verify')
    case = _case(client, auth, [first])
    cid = case['id']
    assert case['status'] == 'open' and case['version'] == 1
    assert client.get(f'/v1/cases/{cid}', headers=auth).json() == case
    case = client.post(f'/v1/cases/{cid}/analyses', headers=auth, json={'analysis_id': second}).json()
    assert case['version'] == 2 and len(case['analysis_ids']) == 2
    graph = client.get(f'/v1/cases/{cid}/graph', headers=auth).json()
    assert graph['case_id'] == cid
    assert any(x['kind'] == 'registrable_domain' for x in graph['nodes'])
    shared = [x for x in graph['shared_indicators'] if x['node_id'] == 'domain:example.com']
    assert len(shared) == 1 and len(shared[0]['analysis_ids']) == 2
    review = client.post(f'/v1/cases/{cid}/reviews', headers=auth, json={
        'decision': 'inconclusive', 'rationale': 'As observacoes ainda nao permitem atribuir controle ou autoria.'})
    assert review.status_code == 201, review.text
    assert review.json()['status'] == 'under_review'
    assert review.json()['reviews'][0]['decision'] == 'inconclusive'
    dossier_response = client.get(f'/v1/cases/{cid}/dossier', headers=auth)
    assert dossier_response.status_code == 200
    assert dossier_response.headers['cache-control'] == 'no-store'
    dossier = dossier_response.json()
    assert dossier['integrity']['digest'] == hashlib.sha256(canonical_bytes(dossier['dossier'])).hexdigest()
    assert dossier_response.json() == client.get(f'/v1/cases/{cid}/dossier', headers=auth).json()
    assert len(dossier['dossier']['analyses']) == 2
    assert len(client.get('/v1/cases', headers=auth).json()) == 1
    assert all('secret' not in str(a) for a in dossier['dossier']['analyses'])
    audit = client.get('/v1/audit', headers=auth).json()['events']
    assert any(event['action'] == 'case.reviewed' for event in audit)
    assert any(event['action'] == 'case.created' for event in audit)


def test_admin_status_transitions_and_conflicts(client, auth):
    case = _case(client, auth)
    cid = case['id']
    url = f'/v1/cases/{cid}/status'
    assert client.patch(url, headers=auth, json={'status': 'closed', 'expected_version': 999}).status_code == 409
    completed = client.patch(url, headers=auth, json={'status': 'closed', 'expected_version': 1})
    assert completed.status_code == 200 and completed.json()['version'] == 2
    assert client.post(f'/v1/cases/{cid}/reviews', headers=auth, json={
        'decision': 'suspected', 'rationale': 'Indicadores tecnicos requerem revisao humana independente.'}).status_code == 409
    assert client.post(f'/v1/cases/{cid}/analyses', headers=auth, json={'analysis_id': str(uuid4())}).status_code == 409
    assert client.patch(url, headers=auth, json={'status': 'closed', 'expected_version': 2}).status_code == 409
    assert client.patch(url, headers=auth, json={'status': 'under_review', 'expected_version': 2}).status_code == 200


def test_case_missing_resources_and_invalid_inputs(client, auth):
    missing = str(uuid4())
    assert client.get(f'/v1/cases/{missing}', headers=auth).status_code == 404
    assert client.get(f'/v1/cases/{missing}/graph', headers=auth).status_code == 404
    assert client.get(f'/v1/cases/{missing}/dossier', headers=auth).status_code == 404
    assert client.post('/v1/cases', headers=auth, json={
        'title': 'Investigacao sem dados', 'analysis_ids': [missing]}).status_code == 404
    assert client.post('/v1/cases', headers=auth, json={'title': 'token=supersegredo'}).status_code == 422
    assert client.post('/v1/cases', headers=auth, json={'title': 'Investigacao valida',
        'analysis_ids': [str(uuid4())] * 21}).status_code == 422
    assert client.get('/v1/cases?limit=150', headers=auth).status_code == 422
    assert client.get('/v1/cases', headers=auth).json() == []


def test_case_review_does_not_modify_independent_risk_assessment(client, auth):
    identifier = _analysis(client, auth, 'example.org/login')
    initial = client.get(f'/v1/analyses/{identifier}', headers=auth).json()
    case = _case(client, auth, [identifier])
    cid = case['id']
    response = client.post(f'/v1/cases/{cid}/reviews', headers=auth, json={
        'decision': 'suspected', 'rationale': 'A revisao e uma hipotese e requer evidencias independentes.'})
    assert response.status_code == 201
    after = client.get(f'/v1/analyses/{identifier}', headers=auth).json()
    assert after == initial
    assert client.post(f'/v1/cases/{cid}/analyses', headers=auth,
                       json={'analysis_id': identifier}).status_code == 409
