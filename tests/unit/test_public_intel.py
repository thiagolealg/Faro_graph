from urllib.parse import parse_qs, urlsplit

import pytest

from faro_api.public_intel import (
    RDAPCollector, CertificateTransparencyCollector, PublicIntelError,
    _validate_provider_url, _event_date, fetch_provider_json,
)


def test_rdap_br_domain_minimizes_pii_and_extracts_dates():
    calls = []
    def fetch(url):
        calls.append(url)
        return {
            'objectClassName': 'domain', 'ldhName': 'exemplo.com.br',
            'events': [
                {'eventAction': 'registration', 'eventDate': '2026-10-01T12:00:00Z'},
                {'eventAction': 'expiration', 'eventDate': '2027-10-01T12:00:00Z'},
                {'eventAction': 'last changed', 'eventDate': '2026-10-15T12:00:00Z'},
            ],
            'nameservers': [{'ldhName': 'ns1.exemplo.com.br.'}, {'ldhName': 'ns2.exemplo.com.br'}],
            'entities': [{'roles': ['registrant'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'NEVER_STORE_NAME_345']]]}],
            'remarks': [{'description': ['NEVER_STORE_PHONE_555']}],
        }
    data = RDAPCollector(fetch).collect('exemplo.com.br')
    assert calls == ['https://rdap.registro.br/domain/exemplo.com.br']
    assert data.status == 'observed'
    assert data.registered_on == '2026-10-01'
    assert data.expires_on == '2027-10-01'
    assert data.changed_on == '2026-10-15'
    assert data.nameservers == ['ns1.exemplo.com.br', 'ns2.exemplo.com.br']
    assert 'NEVER_STORE' not in data.model_dump_json()


def test_rdap_com_and_net_only_known_endpoints():
    seen=[]
    def fake(url):
        seen.append(url)
        domain=url.rsplit('/', 1)[-1]
        return {'objectClassName':'domain','ldhName':domain}
    collector = RDAPCollector(fake)
    assert collector.collect('example.com').status == 'observed'
    assert collector.collect('example.net').status == 'observed'
    assert seen == ['https://rdap.verisign.com/com/v1/domain/example.com', 'https://rdap.verisign.com/net/v1/domain/example.net']
    unsupported=collector.collect('example.org')
    assert unsupported.status == 'unsupported'
    assert unsupported.error_codes == ['TldNotSupported']
    assert len(seen) == 2


def test_rdap_fails_closed_on_mismatched_domain_and_malformed_data():
    result=RDAPCollector(lambda _: {'objectClassName':'domain','ldhName':'attacker.com'}).collect('example.com')
    assert result.status == 'unavailable'
    assert result.error_codes == ['InvalidProviderData']
    assert not result.nameservers


def test_ct_deduplicates_filters_unrelated_and_avoids_raw_sans():
    calls=[]
    def fake(url):
        calls.append(url)
        return [
            {'id': 12, 'name_value':'api.example.com\n*.example.com', 'not_before':'2026-01-01 10:00:00', 'issuer_name':'CA Example'},
            {'id': 12, 'name_value':'api.example.com', 'not_before':'2026-01-01 10:00:00', 'issuer_name':'CA Example'},
            {'id': 13, 'name_value':'otherexample.com', 'not_before':'2026-11-01T10:00:00Z'},
            {'id': 14, 'name_value':'login.example.com', 'not_before':'2026-10-15T10:00:00Z', 'issuer_name':'CA Other', 'owner':'PRIVATE_ABC'},
        ]
    result=CertificateTransparencyCollector(fake).collect('example.com')
    assert result.status == 'observed'
    assert result.certificates_matched == 2
    assert result.latest_not_before == '2026-10-15'
    assert result.issuers == ['CA Example', 'CA Other']
    assert 'PRIVATE_ABC' not in result.model_dump_json()
    parsed=urlsplit(calls[0]); assert parsed.hostname=='crt.sh'
    assert parse_qs(parsed.query)=={'q':['example.com'],'output':['json']}


def test_ct_empty_does_not_claim_safety():
    result=CertificateTransparencyCollector(lambda _: []).collect('example.com')
    assert result.status=='observed' and result.certificates_matched==0
    assert 'nao confirma' in result.note


def test_ct_invalid_payload_is_unavailable_without_leaking_exception():
    def explode(_):
        raise RuntimeError('PRIVATE_TOKEN_SHOULD_NOT_APPEAR')
    for cls in (RDAPCollector,CertificateTransparencyCollector):
        data=cls(explode).collect('example.com')
        assert data.status=='unavailable'
        assert 'PRIVATE_TOKEN' not in data.model_dump_json()


def test_provider_url_policy_prohibits_ssrf_redirect_and_arbitrary_hosts():
    for url in (
        'http://crt.sh/?q=example.com',
        'https://localhost/rdap/domain/example.com',
        'https://127.0.0.1/',
        'https://crt.sh.attacker.example/',
        'https://user:pass@crt.sh/',
        'https://crt.sh:8443/',
        'https://crt.sh/#foo',
        'https://crt.sh/payload?output=json&q=example.com',
        'https://crt.sh/?q=example.com&output=json&extra=unsafe',
        'https://rdap.verisign.com/com/v1/domain/example.net',
        'https://rdap.verisign.com/com/v1/domain/example.com?url=http://127.0.0.1',
        'https://rdap.registro.br/other/path',
    ):
        with pytest.raises(PublicIntelError):
            _validate_provider_url(url)
    with pytest.raises(PublicIntelError):
        fetch_provider_json('http://169.254.169.254/latest/meta-data')


def test_date_values_are_validated_and_normalized():
    assert _event_date('2026-11-07T10:11:12Z') == '2026-11-07'
    assert _event_date('2026-11-07 10:11:12') == '2026-11-07'
    assert _event_date('2026-99-99T00:00:00Z') is None
    assert _event_date('2026-11-07T10:11:12Z;evil') is None


def test_real_transport_rejects_http_redirect_without_following(monkeypatch):
    import faro_api.public_intel as intel
    from urllib.error import HTTPError
    from io import BytesIO
    class FakeOpener:
        def open(self, request, timeout):
            assert timeout <= 3.0
            raise HTTPError(request.full_url, 302, 'moved', {'Location': 'http://127.0.0.1/'}, BytesIO(b''))
    monkeypatch.setattr(intel, 'build_opener', lambda *args: FakeOpener())
    with pytest.raises(PublicIntelError, match='ProviderHTTPError'):
        fetch_provider_json('https://rdap.verisign.com/com/v1/domain/example.com')


def test_real_transport_rejects_oversize_and_non_json(monkeypatch):
    import faro_api.public_intel as intel
    class FakeResponse:
        status=200
        headers={'Content-Type':'application/json'}
        def __init__(self, payload): self.payload=payload
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, length): return self.payload[:length]
    class FakeOpener:
        def __init__(self, payload): self.payload=payload
        def open(self, request, timeout): return FakeResponse(self.payload)
    monkeypatch.setattr(intel, 'build_opener', lambda *args: FakeOpener(b'x'*500_000))
    with pytest.raises(PublicIntelError, match='ResponseTooLarge'):
        fetch_provider_json('https://rdap.verisign.com/com/v1/domain/example.com')
    class WrongContent(FakeOpener):
        def open(self, request, timeout):
            result=FakeResponse(b'<html>')
            result.headers={'Content-Type':'text/html'}
            return result
    monkeypatch.setattr(intel, 'build_opener', lambda *args: WrongContent(b''))
    with pytest.raises(PublicIntelError, match='InvalidContentType'):
        fetch_provider_json('https://rdap.registro.br/domain/example.br')
