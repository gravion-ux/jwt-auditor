"""JWT decoding (no signature verification -- this is an auditor, not a
validator). Parsing is strict: anything malformed raises TokenError so the
CLI can report it as a usage error instead of auditing garbage."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field


class TokenError(ValueError):
    """Raised when a string is not a well-formed JWT."""


def _b64url_decode(segment: str, what: str) -> bytes:
    if not segment:
        raise TokenError(f"{what} segment is empty")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise TokenError(f"{what} segment is not valid base64url: {exc}") from exc


class _DuplicateTracker:
    """object_pairs_hook that records keys appearing more than once."""

    def __init__(self):
        self.duplicates = []

    def hook(self, pairs):
        obj = {}
        for key, value in pairs:
            if key in obj and key not in self.duplicates:
                self.duplicates.append(key)
            obj[key] = value
        return obj


def _decode_json_segment(segment: str, what: str):
    raw = _b64url_decode(segment, what)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TokenError(f"{what} segment is not UTF-8 JSON: {exc}") from exc
    tracker = _DuplicateTracker()
    try:
        data = json.loads(text, object_pairs_hook=tracker.hook)
    except json.JSONDecodeError as exc:
        raise TokenError(f"{what} segment is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TokenError(f"{what} segment must be a JSON object")
    return data, tracker.duplicates


@dataclass(frozen=True)
class Token:
    raw: str
    header: dict
    payload: dict
    signature: bytes
    signing_input: bytes  # the ASCII "header.payload" the signature covers
    header_duplicates: list = field(default_factory=list)
    payload_duplicates: list = field(default_factory=list)

    @property
    def alg(self) -> str:
        alg = self.header.get("alg")
        return alg if isinstance(alg, str) else ""


def decode_token(text: str) -> Token:
    """Decode a JWT string into a Token. Raises TokenError if malformed."""
    if text is None:
        raise TokenError("token is empty")
    token = str(text).strip()
    if not token:
        raise TokenError("token is empty")
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError(
            f"a JWT has exactly 3 dot-separated segments, got {len(parts)}"
        )
    header, header_dups = _decode_json_segment(parts[0], "header")
    payload, payload_dups = _decode_json_segment(parts[1], "payload")
    signature = b""
    if parts[2]:
        signature = _b64url_decode(parts[2], "signature")
    return Token(
        raw=token,
        header=header,
        payload=payload,
        signature=signature,
        signing_input=".".join(parts[:2]).encode("ascii"),
        header_duplicates=header_dups,
        payload_duplicates=payload_dups,
    )
