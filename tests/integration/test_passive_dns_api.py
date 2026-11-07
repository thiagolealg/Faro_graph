from fastapi.testclient import TestClient
from faro_api.main import create_app
from faro_api.schemas import DNSObservation, DNSRecord


class FakeCollector:
    def __init__(self, *args, **kwargs):
        pass

    def collect(self, hostname):
        return DNSObservation(status='observed', resolver='public_recursive_dns', checked_at='2026-11-07T12:00:00+00:00',
            records=[DNSRecord(type='A', value='8.8.8.8', ttl=60)], error_codes=[], note='Somente observacao DNS')


def test_dns_enrichment_optional_and_graph_uses_observed_edges(tmp_path, monkeypatch):
    monkeypatch.setenv('FARO_DNS_ENABLED', '1')
    monkeypatch.setattr('faro_api.main.PassiveDNSCollector', FakeCollector)
    with TestClient(create_app(db_path=str(tmp_path/'test.sqlite'), api_key='test-secret')) as c:
        assert c.get('/healthz').json()['passive_dns_enabled'] is True
        r = c.post('/v1/analyses', headers={'X-Faro-Api-Key': 'test-secret'}, json={'url':'https://example.com'})
        assert r.status_code == 201
        data = r.json()
        assert data['passive_dns']['status'] == 'observed'
        assert any(e['source']=='public_recursive_dns' and e['impact']==0 for e in data['evidence'])
        graph = c.get('/v1/analyses/'+data['analysis_id']+'/graph',headers={'X-Faro-Api-Key': 'test-secret'}).json()
        assert any(x['target']=='ip:8.8.8.8' and x['certainty']=='observed' and x['evidence_id']=='ev-dns-001' for x in graph['edges'])
        assert data['assessment']['level']=='inconclusive'
