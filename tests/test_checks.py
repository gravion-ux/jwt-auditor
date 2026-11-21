"""Tests for every audit check family."""

import base64
import hashlib
import hmac
import json

from jwt_auditor.checks import audit_token
from jwt_auditor.decode import decode_token

NOW = 1_800_000_000  # fixed "now" so lifetime checks are deterministic


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint(header, payload, key=None, digest=hashlib.sha256):
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    p = b64(json.dumps(payload, separators=(",", ":")).encode())
    if key is None:
        return f"{h}.{p}."
    sig = hmac.new(key, f"{h}.{p}".encode(), digest).digest()
    return f"{h}.{p}.{b64(sig)}"


def ids(findings):
    return {f.check_id for f in findings}


def healthy_payload(**overrides):
    payload = {"sub": "1", "iat": NOW - 60, "exp": NOW + 3600}
    payload.update(overrides)
    return payload


def test_alg_none_is_critical():
    token = decode_token(mint({"alg": "none"}, healthy_payload()))
    findings = audit_token(token, now=NOW)
    assert "alg-none" in ids(findings)
    assert next(f for f in findings if f.check_id == "alg-none").severity == "critical"


def test_empty_signature_with_real_alg_is_high():
    token = decode_token(mint({"alg": "RS256"}, healthy_payload()))
    assert "empty-signature" in ids(audit_token(token, now=NOW))


def test_missing_alg_is_high():
    token = decode_token(mint({"typ": "JWT"}, healthy_payload(), key=b"x" * 40))
    assert "alg-missing" in ids(audit_token(token, now=NOW))


def test_weak_secret_dictionary_hit_is_critical():
    token = decode_token(mint({"alg": "HS256"}, healthy_payload(), key=b"secret"))
    findings = audit_token(token, now=NOW)
    hit = next(f for f in findings if f.check_id == "weak-hmac-secret")
    assert hit.severity == "critical"
    assert "'secret'" in hit.detail


def test_strong_secret_is_not_cracked():
    token = decode_token(mint(
        {"alg": "HS256"}, healthy_payload(),
        key=b"9f2c7a41-b8d3-4e6f-a1c5-77d209e83b4f"))
    assert "weak-hmac-secret" not in ids(audit_token(token, now=NOW))


def test_wordlist_secret_is_cracked():
    token = decode_token(mint(
        {"alg": "HS256"}, healthy_payload(), key=b"corp-signing-2024"))
    findings = audit_token(token, extra_secrets=["corp-signing-2024"], now=NOW)
    assert "weak-hmac-secret" in ids(findings)


def test_asymmetric_alg_is_not_dictionary_attacked():
    token = decode_token(mint({"alg": "RS256"}, healthy_payload(), key=b"secret"))
    assert "weak-hmac-secret" not in ids(audit_token(token, now=NOW))


def test_embedded_key_params_flagged():
    token = decode_token(mint(
        {"alg": "RS256", "jku": "https://evil.example/keys.json"},
        healthy_payload(), key=b"x" * 40))
    assert "embedded-key-material" in ids(audit_token(token, now=NOW))


def test_kid_injection_pattern_flagged():
    token = decode_token(mint(
        {"alg": "HS256", "kid": "../../dev/null"},
        healthy_payload(), key=b"x" * 40))
    assert "kid-injection-pattern" in ids(audit_token(token, now=NOW))


def test_duplicate_keys_flagged():
    header = b64(b'{"alg":"HS256","alg":"HS256"}')
    payload = b64(json.dumps(healthy_payload()).encode())
    token = decode_token(f"{header}.{payload}.{b64(b'sig')}")
    assert "duplicate-json-keys" in ids(audit_token(token, now=NOW))


def test_missing_expiry_flagged():
    payload = healthy_payload()
    del payload["exp"]
    token = decode_token(mint({"alg": "HS256"}, payload, key=b"x" * 40))
    assert "missing-expiry" in ids(audit_token(token, now=NOW))


def test_expired_token_flagged_low():
    token = decode_token(mint(
        {"alg": "HS256"}, healthy_payload(exp=NOW - 10, iat=NOW - 4000),
        key=b"x" * 40))
    findings = audit_token(token, now=NOW)
    hit = next(f for f in findings if f.check_id == "token-expired")
    assert hit.severity == "low"


def test_long_lived_token_flagged():
    token = decode_token(mint(
        {"alg": "HS256"},
        healthy_payload(exp=NOW + 90 * 86400),
        key=b"x" * 40))
    assert "long-lived-token" in ids(audit_token(token, now=NOW))


def test_sensitive_claims_flagged():
    token = decode_token(mint(
        {"alg": "HS256"}, healthy_payload(password="hunter2"), key=b"x" * 40))
    assert "sensitive-claims" in ids(audit_token(token, now=NOW))


def test_healthy_token_has_no_findings():
    token = decode_token(mint(
        {"alg": "HS256", "typ": "JWT", "kid": "2026-key-1"},
        healthy_payload(), key=b"x" * 40))
    assert audit_token(token, now=NOW) == []

def test_missing_iat_flagged():
    payload = healthy_payload()
    del payload["iat"]
    token = decode_token(mint({"alg": "HS256"}, payload, key=b"x" * 40))
    findings = audit_token(token, now=NOW)
    assert ids(findings) == {"missing-issued-at"}
    hit = next(f for f in findings if f.check_id == "missing-issued-at")
    assert hit.severity == "low"


def test_missing_iat_keeps_token_low_risk():
    from jwt_auditor.report import grade, risk_score

    payload = healthy_payload()
    del payload["iat"]
    token = decode_token(mint({"alg": "HS256"}, payload, key=b"x" * 40))
    findings = audit_token(token, now=NOW)
    assert risk_score(findings) == 3
    assert grade(risk_score(findings)) == "low"


def test_healthy_token_with_iat_has_no_missing_iat_finding():
    token = decode_token(mint({"alg": "HS256"}, healthy_payload(), key=b"x" * 40))
    findings = audit_token(token, now=NOW)
    assert "missing-issued-at" not in ids(findings)
