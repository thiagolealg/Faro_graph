"""Opt-in enterprise OIDC and server-side web sessions.

Authorization code + PKCE + nonce, pinned issuer/audience/RS256 ID token,
explicit identity allowlist, one-use state, opaque session cookie and CSRF.
No self-registration; service API keys remain separate from browser sessions.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

from .auth import Principal
from .storage import Storage

SESSION_COOKIE = '__Host-faro_session'
STATE_COOKIE = '__Host-faro_oidc_state'
CSRF_COOKIE = '__Host-faro_csrf'
SESSION_TTL = 8 * 3600
PENDING_TTL = 300


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def _opaque() -> str:
    return secrets.token_urlsafe(32)


def _https_url(value: str, *, origin: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > 2000:
        raise ValueError('URL OIDC invalida')
    p = urlsplit(value)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment or p.query:
        raise ValueError('OIDC exige URLs HTTPS configuradas e sem parametros')
    if p.port not in (None, 443):
        raise ValueError('Porta HTTPS nao aprovada')
    if origin and (p.path not in ('', '/') or p.port is not None):
        raise ValueError('Origem deve ser HTTPS e sem caminho')
    return value.rstrip('/') if origin else value


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    authorize_url: str
    token_url: str
    jwks_url: str
    client_id: str
    redirect_uri: str
    ui_origin: str
    client_secret: str | None
    users: dict[str, Principal]

    @classmethod
    def from_env(cls, value: str | None = None, users_value: str | None = None) -> 'OIDCConfig | None':
        raw = value if value is not None else os.getenv('FARO_OIDC_CONFIG')
        if not raw:
            return None
        if users_value is None:
            users_value = os.getenv('FARO_OIDC_USERS_JSON')
        try:
            data = json.loads(raw)
            identities = json.loads(users_value or '')
            if not isinstance(identities, list) or not identities:
                raise ValueError('Allowlist OIDC obrigatoria')
            users = {}
            for item in identities:
                sub = item['subject']
                tenant_id = item['tenant_id']
                actor_id = item['actor_id']
                role = item['role']
                quota = int(item.get('hourly_quota', 60))
                if (not all(isinstance(s, str) and 1 <= len(s) <= 100 for s in
                            (sub, tenant_id, actor_id)) or role not in ('reader', 'analyst', 'admin')
                        or not 1 <= quota <= 100000 or sub in users):
                    raise ValueError('Usuario OIDC invalido ou duplicado')
                users[sub] = Principal(tenant_id, actor_id, role, 'oidc:' + hashlib.sha256(sub.encode('utf-8')).hexdigest(), quota)
            issuer = _https_url(data['issuer'])
            auth = _https_url(data['authorize_url'])
            token = _https_url(data['token_url'])
            jwks = _https_url(data['jwks_url'])
            redirect = _https_url(data['redirect_uri'])
            origin = _https_url(data['ui_origin'], origin=True)
            if redirect != origin + '/v1/auth/callback':
                raise ValueError('Callback deve ser a rota OIDC fixa da origem')
            client_id = data['client_id']
            secret = data.get('client_secret')
            if not isinstance(client_id, str) or not 1 <= len(client_id) <= 200:
                raise ValueError('client_id invalido')
            if secret is not None and (not isinstance(secret, str) or len(secret) < 16):
                raise ValueError('client_secret invalido')
            return cls(issuer, auth, token, jwks, client_id, redirect, origin, secret, users)
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError('Configuracao OIDC invalida; verifique issuer, endpoints e allowlist') from exc


class OIDCService:
    def __init__(self, config: OIDCConfig, storage: Storage):
        self.config = config
        self.db = storage

    def begin(self) -> tuple[str, str]:
        state, nonce, verifier = _opaque(), _opaque(), _opaque()
        self.db.create_oidc_pending(_hash(state), verifier, nonce, int(time.time()) + PENDING_TTL)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
        params = {'response_type': 'code', 'client_id': self.config.client_id,
                  'redirect_uri': self.config.redirect_uri, 'scope': 'openid',
                  'state': state, 'nonce': nonce, 'code_challenge': challenge,
                  'code_challenge_method': 'S256'}
        return self.config.authorize_url + '?' + urlencode(params), state

    def _token(self, code: str, verifier: str) -> str:
        payload = {'grant_type': 'authorization_code', 'code': code, 'client_id': self.config.client_id,
                   'redirect_uri': self.config.redirect_uri, 'code_verifier': verifier}
        auth = httpx.BasicAuth(self.config.client_id, self.config.client_secret) if self.config.client_secret else None
        with httpx.Client(timeout=7.0, follow_redirects=False, trust_env=False) as client:
            response = client.post(self.config.token_url, data=payload, auth=auth)
        if response.status_code != 200 or len(response.content) > 32768:
            raise ValueError('Provedor recusou intercambio OIDC')
        result = response.json()
        id_token = result.get('id_token') if isinstance(result, dict) else None
        if not isinstance(id_token, str) or len(id_token) > 16000:
            raise ValueError('ID token ausente ou invalido')
        return id_token

    def _validate(self, id_token: str, nonce: str) -> Principal:
        header = jwt.get_unverified_header(id_token)
        kid = header.get('kid')
        if header.get('alg') != 'RS256' or not isinstance(kid, str) or len(kid) > 150:
            raise ValueError('Algoritmo ou chave ID token nao autorizada')
        with httpx.Client(timeout=7.0, follow_redirects=False, trust_env=False) as client:
            response = client.get(self.config.jwks_url)
        if response.status_code != 200 or len(response.content) > 65536:
            raise ValueError('JWKS indisponivel')
        jwks = response.json()
        keys = jwks.get('keys', []) if isinstance(jwks, dict) else []
        matches = [k for k in keys if isinstance(k, dict) and k.get('kid') == kid and
                   k.get('kty') == 'RSA' and k.get('use', 'sig') == 'sig' and
                   k.get('alg', 'RS256') == 'RS256']
        if len(matches) != 1:
            raise ValueError('Chave JWKS ausente ou ambigua')
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matches[0])
        claims = jwt.decode(id_token, public_key, algorithms=['RS256'], issuer=self.config.issuer,
                            audience=self.config.client_id, leeway=30,
                            options={'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'nonce']})
        if not isinstance(claims.get('nonce'), str) or not secrets.compare_digest(claims['nonce'], nonce):
            raise ValueError('Nonce OIDC incorreto')
        if 'azp' in claims and claims['azp'] != self.config.client_id:
            raise ValueError('Authorized party OIDC incorreta')
        principal = self.config.users.get(claims.get('sub'))
        if principal is None:
            raise PermissionError('Identidade nao autorizada para FARO')
        return principal

    def finish(self, state: str, state_cookie: str | None, code: str) -> tuple[str, str]:
        if (not state_cookie or len(state) > 256 or len(code) > 4096 or
                not secrets.compare_digest(state, state_cookie)):
            raise ValueError('Estado OIDC invalido')
        pending = self.db.consume_oidc_pending(_hash(state))
        if not pending:
            raise ValueError('Autorizacao expirada ou ja utilizada')
        verifier, nonce = pending
        token = self._token(code, verifier)
        principal = self._validate(token, nonce)
        session, csrf = _opaque(), _opaque()
        self.db.create_web_session(_hash(session), _hash(csrf), principal, int(time.time()) + SESSION_TTL)
        self.db.audit(principal.tenant_id, principal.actor_id, 'auth.oidc.login', None)
        return session, csrf

    def get(self, cookie: str | None) -> tuple[Principal, str] | None:
        if not cookie or len(cookie) > 256:
            return None
        found = self.db.get_web_session(_hash(cookie))
        if not found:
            return None
        principal, csrf_hash = found
        # Revalidate on every request: removing a user or changing their role in the
        # allowlist invalidates persisted sessions after a configuration restart.
        if not any(p == principal for p in self.config.users.values()):
            self.db.revoke_web_session(_hash(cookie))
            return None
        return principal, csrf_hash

    def verify_csrf(self, csrf: str | None, expected_hash: str) -> bool:
        return bool(csrf and len(csrf) <= 256 and secrets.compare_digest(_hash(csrf), expected_hash))

    def logout(self, cookie: str):
        self.db.revoke_web_session(_hash(cookie))
