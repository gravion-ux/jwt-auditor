"""Tests for JWT decoding and malformed-input handling."""

import base64
import json

import pytest

from jwt_auditor.decode import TokenError, decode_token


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(header, payload, signature=b"sig"):
    return ".".join([
        b64(json.dumps(header).encode()),
        b64(json.dumps(payload).encode()),
        b64(signature),
    ])


def test_decode_round_trip():
    token = decode_token(make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}))
    assert token.alg == "HS256"
    assert token.payload == {"sub": "1"}
    assert token.signature == b"sig"


def test_decode_strips_bearer_prefix_and_whitespace():
    raw = make_token({"alg": "HS256"}, {"sub": "1"})
    assert decode_token("  Bearer " + raw + "\n").payload == {"sub": "1"}


def test_decode_rejects_wrong_segment_count():
    with pytest.raises(TokenError, match="3 dot-separated"):
        decode_token("only.two")
    with pytest.raises(TokenError, match="3 dot-separated"):
        decode_token("a.b.c.d")


def test_decode_rejects_empty_and_garbage():
    with pytest.raises(TokenError):
        decode_token("")
    with pytest.raises(TokenError):
        decode_token("!!!.@@@.###")


def test_decode_rejects_non_object_header():
    raw = ".".join([b64(b'["not", "an", "object"]'), b64(b"{}"), b64(b"x")])
    with pytest.raises(TokenError, match="must be a JSON object"):
        decode_token(raw)


def test_decode_detects_duplicate_keys():
    header = b64(b'{"alg": "HS256", "alg": "none"}')
    payload = b64(b'{"sub": "1", "sub": "2"}')
    token = decode_token(".".join([header, payload, b64(b"sig")]))
    assert token.header_duplicates == ["alg"]
    assert token.payload_duplicates == ["sub"]


def test_decode_empty_signature_is_allowed_to_parse():
    raw = make_token({"alg": "none"}, {"sub": "1"}, signature=b"")
    token = decode_token(raw)
    assert token.signature == b""
