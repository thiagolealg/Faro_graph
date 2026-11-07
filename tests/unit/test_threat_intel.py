"""Testes unitarios do snapshot de reputacao sem rede."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from faro_api.threat_intel import ThreatIntelSnapshot
from faro_api.url_security import normalize_url


NOW = datetime.now(timezone.utc)


def record(kind="url", indicator="https://example.com/verify", category="phishing", source="licensed_test_feed", *, expired=False, **extra):
    obj = {"type": kind, "indicator": indicator, "category": category, "source": source,
           "observed_at": (NOW - timedelta(days=3)).isoformat(),
           "expires_at": (NOW - timedelta(days=1) if expired else NOW + timedelta(days=4)).isoformat()}
    obj.update(extra)
    return obj


def write(tmp_path, *records):
    path = tmp_path / "feed.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return str(path)


def test_exact_url_match(tmp_path):
    intel = ThreatIntelSnapshot(write(tmp_path, record()))
    hit = intel.check(normalize_url("https://example.com/verify"))
    assert hit.status == "matched"
    assert hit.matches[0].source == "licensed_test_feed"
    assert hit.matches[0].indicator_type == "url"
    assert len(hit.snapshot_sha256) == 64
    assert intel.check(normalize_url("https://example.com/other")).status == "no_match"


def test_expired_and_future_records_do_not_report_a_threat(tmp_path):
    intel = ThreatIntelSnapshot(write(tmp_path, record(expired=True)))
    assert intel.check(normalize_url("https://example.com/verify")).status == "no_match"
    with pytest.raises(ValueError, match="validade"):
        ThreatIntelSnapshot(write(tmp_path, record(observed_at=(NOW + timedelta(days=1)).isoformat())))


def test_hostname_matches_only_exact_host(tmp_path):
    intel = ThreatIntelSnapshot(write(tmp_path, record(kind="hostname", indicator="foo.example.com")))
    assert intel.check(normalize_url("https://foo.example.com/path")).status == "matched"
    assert intel.check(normalize_url("https://example.com/path")).status == "no_match"
    assert intel.check(normalize_url("https://a.foo.example.com/path")).status == "no_match"


@pytest.mark.parametrize("obj", [
    record(indicator="https://example.com/verify?token=secret"),
    record(indicator="https://example.com/reset/SECRET0123456789LONG0123"),
    record(indicator="https://example.com/verify#fragment"),
    record(kind="hostname", indicator="EXAMPLE.COM"),
    record(kind="hostname", indicator="https://example.com"),
    record(category="whatever"),
    record(source="../evil"),
    record(expires_at=(NOW + timedelta(days=100)).isoformat()),
    record(type="other"),
])
def test_reject_invalid_feed_rows(tmp_path, obj):
    with pytest.raises(ValueError, match="feed invalido"):
        ThreatIntelSnapshot(write(tmp_path, obj))


def test_reject_unknown_fields_and_missing_fields(tmp_path):
    with pytest.raises(ValueError, match="feed invalido"):
        ThreatIntelSnapshot(write(tmp_path, record(secrets="must-not-accept")))
    incomplete = record()
    del incomplete["source"]
    with pytest.raises(ValueError, match="feed invalido"):
        ThreatIntelSnapshot(write(tmp_path, incomplete))


def test_reject_excessive_size_and_symlink(tmp_path):
    p = tmp_path / "too-big.jsonl"
    p.write_bytes(b" " * 2_000_001)
    with pytest.raises(ValueError, match="tamanho"):
        ThreatIntelSnapshot(str(p))
    p.unlink()
    target = tmp_path / "feed.jsonl"
    target.write_text(json.dumps(record()))
    p.symlink_to(target)
    with pytest.raises(ValueError, match="nao simbolico"):
        ThreatIntelSnapshot(str(p))


def test_deduplicate_records_of_same_source(tmp_path):
    intel = ThreatIntelSnapshot(write(tmp_path, record(), record()))
    assert len(intel.check(normalize_url("https://example.com/verify")).matches) == 1
