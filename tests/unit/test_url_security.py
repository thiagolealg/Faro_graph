import pytest
from faro_api.url_security import normalize_url, URLValidationError


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://10.0.0.4", "http://192.168.1.1", "http://[::1]/",
    "http://169.254.169.254/latest", "ftp://example.com", "http://user:pass@example.com",
    "https://localhost", "https://node.internal", "https://example.com:8080", 
    "https://example.com\\@127.0.0.1", "https://example.com\nX-Injected: true", "http://[fe80::1]",
    "http://host.local", "https://foo..example.com", "https://-example.com", "//example.com",
])
def test_rejects_unsafe(url):
    with pytest.raises(URLValidationError):
        normalize_url(url)


def test_strips_query_fragment_and_lowercases():
    target = normalize_url("HTTPS://Account.Example.COM/path?token=VERYSECRET#fragment")
    assert target.url == "https://account.example.com/path"
    assert target.hostname == "account.example.com"
    assert target.registrable_domain == "example.com"


def test_brazilian_suffix():
    assert normalize_url("https://login.nubank.com.br").registrable_domain == "nubank.com.br"


def test_idna():
    assert normalize_url("https://exämple.com").is_idn is True


def test_redacts_long_path_token():
    target = normalize_url("https://example.com/reset/veryLongResetToken0123456789abcd?access_key=secret")
    assert "veryLongResetToken" not in target.url
    assert "secret" not in target.url
    assert "[REDACTED]" in target.url
