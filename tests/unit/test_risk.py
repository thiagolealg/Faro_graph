from faro_api.risk import evaluate
from faro_api.url_security import normalize_url


def test_legitimate_benign_is_inconclusive():
    assessment, evidence, extra = evaluate(normalize_url("https://www.example.com/"), None)
    assert assessment.level == "inconclusive"
    assert assessment.confidence == "low"
    assert not evidence


def test_brand_lookalike_login_flags_suspicion():
    assessment, evidence, extra = evaluate(normalize_url("https://paypal-verificacao.example"), '<form action="https://collect.example/submit"><input type="password"></form>')
    assert assessment.level in {"high", "critical"}
    assert any(e.code == "possible_brand_impersonation" for e in evidence)
    assert any(e.code == "cross_domain_sensitive_form" for e in evidence)
    assert extra["form_action_hosts"] == ["collect.example"]


def test_official_brand_is_not_impersonation():
    _, evidence, extra = evaluate(normalize_url("https://login.paypal.com"), None)
    assert not any(e.code == "possible_brand_impersonation" for e in evidence)
    assert extra["brand_candidates"] == []


def test_password_alone_is_not_phishing_confirmation():
    result, evidence, _ = evaluate(normalize_url("https://example.com/login"), '<form><input type="password"></form>')
    assert result.level != "critical"
    assert result.classification == "suspicion_only"
