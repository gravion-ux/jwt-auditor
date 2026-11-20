"""Weak HMAC secret dictionary.

A deliberately small list of the secrets that show up again and again in
tutorials, default configurations and leaked code -- the first thing an
attacker tries against an HS256/HS384/HS512 token. For a real engagement,
supply a larger wordlist with --wordlist.
"""

from __future__ import annotations

import hashlib
import hmac

BUILTIN_SECRETS = (
    "",
    "secret",
    "your-256-bit-secret",
    "your-secret-key",
    "your_jwt_secret",
    "jwt-secret",
    "jwtsecret",
    "mysecret",
    "my-secret",
    "supersecret",
    "super-secret",
    "secretkey",
    "secret-key",
    "changeme",
    "change-me",
    "password",
    "password123",
    "123456",
    "12345678",
    "admin",
    "letmein",
    "qwerty",
    "default",
    "test",
    "dev",
    "key",
    "private",
    "signing-key",
    "signingkey",
    "token-secret",
    "auth-secret",
    "keyboard cat",
    "s3cr3t",
    "p@ssw0rd",
    "master",
    "demo",
    "sample",
    "example",
    "jsonwebtoken",
    "jwt",
    "hs256-secret",
    "shhhhh",
    "hush",
    "foobar",
    "abc123",
    "passw0rd",
    "god",
    "login",
)

_HMAC_DIGESTS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def is_hmac_alg(alg: str) -> bool:
    return alg in _HMAC_DIGESTS


def find_weak_secret(token, extra_secrets=()):
    """Return the dictionary secret that verifies the token's signature,
    or None. Only applies to HMAC algorithms (HS256/384/512)."""
    digest = _HMAC_DIGESTS.get(token.alg)
    if digest is None or not token.signature:
        return None
    seen = set()
    for candidate in list(BUILTIN_SECRETS) + list(extra_secrets):
        if candidate in seen:
            continue
        seen.add(candidate)
        expected = hmac.new(
            candidate.encode("utf-8"), token.signing_input, digest
        ).digest()
        if hmac.compare_digest(expected, token.signature):
            return candidate
    return None


def load_wordlist(path):
    """Load extra candidate secrets (one per line, '#' comments) from a file."""
    secrets = []
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                secrets.append(line)
    return secrets
