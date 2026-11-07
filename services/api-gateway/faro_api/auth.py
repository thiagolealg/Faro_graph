"""Local API-key authentication with tenant scoping, actor roles and rotation.

Configuration must be managed as a secret; FARO_TENANTS_JSON is not logged.
A future OIDC integration can replace the credential resolver without changing
request-level tenant isolation.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from typing import Literal

Role = Literal['reader', 'analyst', 'admin']


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor_id: str
    role: Role
    key_id: str
    hourly_quota: int


class KeyRegistry:
    def __init__(self, legacy_key: str | None, tenants_json: str | None):
        self._by_hash: dict[str, Principal] = {}
        if tenants_json:
            try:
                entries = json.loads(tenants_json)
                if not isinstance(entries, list) or not entries:
                    raise ValueError('Lista de tenants vazia')
                for tenant in entries:
                    tenant_id = tenant['tenant_id']
                    quota = int(tenant.get('hourly_quota', 60))
                    if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > 80:
                        raise ValueError('tenant_id invalido')
                    if quota < 1 or quota > 100000:
                        raise ValueError('hourly_quota fora do limite')
                    for item in tenant['keys']:
                        role = item['role']
                        if role not in {'reader', 'analyst', 'admin'}:
                            raise ValueError('role invalido')
                        key = item['key']
                        actor_id = item['actor_id']
                        key_id = item['key_id']
                        if not all(isinstance(x, str) and x for x in (key, actor_id, key_id)) or len(key) < 16:
                            raise ValueError('Credencial invalida (minimo 16 caracteres)')
                        digest = self._digest(key)
                        if digest in self._by_hash:
                            raise ValueError('Chave duplicada')
                        self._by_hash[digest] = Principal(tenant_id, actor_id, role, key_id, quota)
            except (KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
                raise RuntimeError('FARO_TENANTS_JSON invalido; confira o formato e os segredos') from exc
        elif legacy_key:
            self._by_hash[self._digest(legacy_key)] = Principal('local', 'local-user', 'admin', 'legacy-local', 60)
        else:
            raise RuntimeError('Configure FARO_TENANTS_JSON ou FARO_API_KEY para a API local')

    @staticmethod
    def _digest(key: str) -> str:
        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def resolve(self, value: str | None) -> Principal | None:
        if not value:
            return None
        # Compare full key digest in constant time for each configured credential.
        digest = self._digest(value)
        for stored, principal in self._by_hash.items():
            if secrets.compare_digest(digest, stored):
                return principal
        return None


def build_registry(legacy_key: str | None, tenants_json: str | None = None) -> KeyRegistry:
    if tenants_json is None:
        tenants_json = os.getenv('FARO_TENANTS_JSON')
    return KeyRegistry(legacy_key, tenants_json)
