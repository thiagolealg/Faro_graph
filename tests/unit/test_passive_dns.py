import pytest
from faro_api.passive_dns import PassiveDNSCollector


class RecordA:
    def __str__(self):
        return '203.0.113.12'


class RecordPublic:
    def __str__(self):
        return '8.8.8.8'


class RecordPrivate:
    def __str__(self):
        return '127.0.0.1'


class RecordMX:
    exchange = 'mx.example.com.'


class RecordNS:
    target = 'ns.example.com.'


class FakeResponse(list):
    rrset = type('RRSet', (), {'ttl': 300})()


class FakeResolver:
    def resolve(self, hostname, kind, *, lifetime):
        assert hostname == 'example.com'
        return FakeResponse({'A': [RecordPublic(), RecordPrivate()], 'AAAA': [], 'MX': [RecordMX()], 'NS': [RecordNS()]}[kind])


class FakeFails:
    def resolve(self, hostname, kind, *, lifetime):
        raise TimeoutError('never expose arbitrary resolver output')


def test_passive_dns_does_not_contact_target_and_filters_private():
    dns = PassiveDNSCollector('1.1.1.1', resolver=FakeResolver()).collect('example.com')
    assert dns.status == 'partial'
    assert sorted((r.type, r.value) for r in dns.records) == [('A', '8.8.8.8'), ('MX', 'mx.example.com'), ('NS', 'ns.example.com')]
    assert dns.error_codes == ['A:non_global_filtered']
    assert dns.resolver == 'public_recursive_dns'
    assert all('127.0.0.1' not in r.value for r in dns.records)


def test_passive_dns_unavailable_is_not_a_clean_result():
    data = PassiveDNSCollector('1.1.1.1', resolver=FakeFails()).collect('example.com')
    assert data.status == 'unavailable'
    assert not data.records
    assert all(x.endswith('ResolverError') for x in data.error_codes)


def test_private_nameserver_configuration_rejected():
    with pytest.raises(ValueError):
        PassiveDNSCollector('127.0.0.1', resolver=FakeResolver())
