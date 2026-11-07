"""Opt-in passive DNS enrichment through a configured public recursive resolver.

No connection to the investigated website is made. No TXT lookup (to avoid
collecting arbitrary data). Network egress is to the *resolver*, not the host.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from .schemas import DNSObservation, DNSRecord


class PassiveDNSCollector:
    def __init__(self, resolver_address: str = '1.1.1.1', *, resolver: Any = None):
        address = ipaddress.ip_address(resolver_address)
        if not address.is_global:
            raise ValueError('Resolvedor DNS deve usar IP global e previamente confiavel')
        self.address = str(address)
        if resolver is None:
            import dns.resolver  # type: ignore[import-untyped]
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [self.address]
            resolver.timeout = 1.0
            resolver.lifetime = 1.5
        self.resolver = resolver

    def collect(self, hostname: str) -> DNSObservation:
        records: list[DNSRecord] = []
        errors: list[str] = []
        for record_type in ('A', 'AAAA', 'MX', 'NS'):
            try:
                response = self.resolver.resolve(hostname, record_type, lifetime=1.5)
                ttl = max(0, min(86400, int(getattr(getattr(response, 'rrset', None), 'ttl', 0))))
                for record in list(response)[:6]:
                    if record_type in {'A', 'AAAA'}:
                        address = ipaddress.ip_address(str(record))
                        if not address.is_global:
                            errors.append(f'{record_type}:non_global_filtered')
                            continue
                        value = str(address)
                    elif record_type == 'MX':
                        value = str(record.exchange).lower().rstrip('.')
                    else:
                        value = str(record.target).lower().rstrip('.')
                    if value and len(value) <= 253:
                        records.append(DNSRecord(type=record_type, value=value, ttl=ttl))
            except Exception as exc:
                # Only the exception's class is retained, never vendor output.
                error_type = type(exc).__name__
                if error_type not in {'NoAnswer', 'NXDOMAIN', 'NoNameservers', 'LifetimeTimeout', 'Timeout'}:
                    error_type = 'ResolverError'
                if error_type != 'NoAnswer':
                    errors.append(f'{record_type}:{error_type}')
        return DNSObservation(
            status='observed' if records and not errors else 'partial' if records else 'unavailable',
            resolver='public_recursive_dns',
            checked_at=datetime.now(timezone.utc).isoformat(),
            records=records,
            error_codes=errors,
            note='Observacoes DNS momentaneas; IPs e provedores compartilhados nao identificam autores de fraude.',
        )
