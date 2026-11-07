from fastapi.testclient import TestClient
from faro_api.main import create_app
from faro_api.schemas import CTObservation, RDAPObservation


class FakeRDAP:
    def __init__(self, *args, **kwargs):
        pass
    def collect(self, domain):
        assert domain == 'example.com'
        return RDAPObservation(status='observed', source='registry_rdap',checked_at='2026-11-07T10:00:00+00:00',
            registered_on='2020-01-01',nameservers=['ns.example.com'],note='RDAP mock')


class FakeCT:
    def __init__(self, *args, **kwargs):
        pass
    def collect(self, domain):
        assert domain == 'example.com'
        return CTObservation(status='observed', source='crt_sh_ct_index',checked_at='2026-11-07T10:00:00+00:00',
            certificates_matched=2,latest_not_before='2026-07-01',issuers=['CA Example'],note='CT mock')


def test_rdap_ct_opt_in_with_enrichment_and_graph(tmp_path, monkeypatch):
    monkeypatch.setenv('FARO_RDAP_ENABLED', '1')
    monkeypatch.setenv('FARO_CT_ENABLED', '1')
    monkeypatch.setattr('faro_api.main.RDAPCollector', FakeRDAP)
    monkeypatch.setattr('faro_api.main.CertificateTransparencyCollector', FakeCT)
    with TestClient(create_app(db_path=str(tmp_path/'db.sqlite'), api_key='local-test')) as c:
        h=c.get('/healthz').json()
        assert h['rdap_enabled'] and h['ct_enabled'] and not h['live_tls_enabled']
        res=c.post('/v1/analyses',headers={'X-Faro-Api-Key':'local-test'},json={'url':'https://example.com'});
        assert res.status_code == 201
        doc=res.json()
        assert doc['rdap']['registered_on']=='2020-01-01'
        assert doc['certificate_transparency']['certificates_matched']==2
        assert any(e['id']=='ev-rdap-001' and e['impact']==0 for e in doc['evidence'])
        assert any(e['id']=='ev-ct-001' and e['impact']==0 for e in doc['evidence'])
        assert doc['assessment']['level']=='inconclusive'
        saved=c.get(f"/v1/analyses/{doc['analysis_id']}",headers={'X-Faro-Api-Key':'local-test'}).json()
        assert saved['rdap']==doc['rdap']
        graph=c.get(f"/v1/analyses/{doc['analysis_id']}/graph",headers={'X-Faro-Api-Key':'local-test'}).json()
        assert any(e['relationship']=='rdap_nameserver_at_scan' and e['evidence_id']=='ev-rdap-001' for e in graph['edges'])
        assert all(e['certainty']=='observed' for e in graph['edges'])


def test_rdap_ct_disabled_does_not_fetch(tmp_path, monkeypatch):
    monkeypatch.delenv('FARO_RDAP_ENABLED', raising=False)
    monkeypatch.delenv('FARO_CT_ENABLED', raising=False)
    with TestClient(create_app(db_path=str(tmp_path/'db.sqlite'), api_key='local-test')) as c:
        res=c.post('/v1/analyses',headers={'X-Faro-Api-Key':'local-test'},json={'url':'https://example.com'})
        assert res.status_code==201
        data=res.json()
        assert data['rdap']['status']=='disabled'
        assert data['certificate_transparency']['status']=='disabled'
