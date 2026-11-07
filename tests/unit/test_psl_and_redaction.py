import pytest
from faro_api.psl import registrable_domain
from faro_api.url_security import URLValidationError, normalize_url


@pytest.mark.parametrize(('host','expected'), [
    ('www.example.com', 'example.com'),
    ('login.foo.co.uk', 'foo.co.uk'),
    ('login.nubank.com.br', 'nubank.com.br'),
    ('user.foo.blogspot.com', 'foo.blogspot.com'),
    ('a.b.ck', 'a.b.ck'),
    ('www.city.kawasaki.jp', 'city.kawasaki.jp'),
    ('com.br', None),
])
def test_psl_private_wildcard_and_exception(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(('input_url','leak'), [
    ('https://example.com/reset/shortkey12', 'shortkey12'),
    ('https://example.com/api_key/letmein', 'letmein'),
    ('https://example.com/session=secret123', 'secret123'),
    ('https://example.com/oauth/joao@example.com', 'joao@example.com'),
    ('https://example.com/code/123456', '123456'),
    ('https://example.com/token/a%252FbSecret', 'a%252FbSecret'),
    ('https://example.com/cpf/12345678909', '12345678909'),
])
def test_redacts_sensitive_path_tokens(input_url, leak):
    assert leak not in normalize_url(input_url).url
    assert '[REDACTED]' in normalize_url(input_url).url


def test_reject_public_suffix_as_registrable():
    with pytest.raises(URLValidationError):
        normalize_url('https://co.uk')


def test_keep_public_safe_path():
    assert normalize_url('https://docs.example.com/public/about.html?apikey=secret').url == 'https://docs.example.com/public/about.html'
