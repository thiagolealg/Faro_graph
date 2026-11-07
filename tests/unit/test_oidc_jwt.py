"""OIDC ID-token verification: issuer, audience, signature, nonce, allowed user."""
import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from faro_api.web_auth import OIDCConfig, OIDCService
from faro_api.storage import Storage


@pytest.fixture
def oidc(tmp_path, monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public = private.public_key().public_numbers()
    url64 = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8, 'big')).rstrip(b'=').decode()
    jwk = {'kty':'RSA','kid':'kid-1','alg':'RS256','use':'sig','n':url64(public.n),'e':url64(public.e)}
    c = {
        'issuer':'https://auth.example.net/realms/faro','authorize_url':'https://auth.example.net/auth',
        'token_url':'https://auth.example.net/token','jwks_url':'https://auth.example.net/jwks',
        'client_id':'faro-test','redirect_uri':'https://faro.example/v1/auth/callback',
        'ui_origin':'https://faro.example'}
    users=[{'subject':'subject-a','tenant_id':'tenant-x','actor_id':'alice','role':'analyst'}]
    config=OIDCConfig.from_env(json.dumps(c),json.dumps(users))
    class Response:
        status_code = 200
        content = json.dumps({'keys':[jwk]}).encode()
        def json(self): return {'keys':[jwk]}
    class Client:
        def __init__(self,**kwargs): self.kwargs=kwargs
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def get(self,url):
            assert url == c['jwks_url']
            assert not self.kwargs['follow_redirects']
            return Response()
    import faro_api.web_auth as auth
    monkeypatch.setattr(auth.httpx, 'Client', Client)
    service=OIDCService(config,Storage(str(tmp_path/'oidc.db')))
    claims={'iss':c['issuer'],'aud':c['client_id'],'sub':'subject-a','nonce':'abc123',
            'iat':int(time.time()),'exp':int(time.time())+600}
    def sign(p, headers=None, algorithm='RS256'):
        return jwt.encode(p,private,algorithm=algorithm,headers=headers or {'kid':'kid-1'})
    return service,claims,sign


def test_valid_id_token(oidc):
    svc,claims,sign=oidc
    principal=svc._validate(sign(claims),'abc123')
    assert principal.actor_id == 'alice' and principal.tenant_id == 'tenant-x'


@pytest.mark.parametrize('field,value', [
    ('nonce','wrong'), ('iss','https://attacker.example'),('aud','attacker-client'),('sub','not-in-allowlist'),
    ('exp', 1),('iat', None),('nonce',None)
])
def test_reject_forged_or_invalid_claim(oidc,field,value):
    svc,claims,sign=oidc
    claims[field]=value
    with pytest.raises((jwt.PyJWTError,ValueError,PermissionError,TypeError)):
        svc._validate(sign(claims),'abc123')


def test_reject_untrusted_kid(oidc):
    svc,claims,sign=oidc
    with pytest.raises(ValueError):
        svc._validate(sign(claims,{'kid':'other'}),'abc123')
