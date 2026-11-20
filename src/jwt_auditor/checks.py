"""Security checks for a decoded JWT.

Every check returns Finding objects with a severity and concrete
remediation text. The checks are purely static/offline: the only
cryptographic operation is trying a small dictionary of well-known weak
HMAC secrets against the token's own signature.
"""

from __future__ import annotations

import re
import time

from .models import Finding
from .secrets import find_weak_secret, is_hmac_alg

# Header parameters that make the token carry (or point at) its own key
# material -- the classic algorithm-confusion / key-injection surface
# (CVE-2018-0114 and friends).
EMBEDDED_KEY_PARAMS = ("jwk", "jku", "x5u", "x5c")

_KID_INJECTION_RE = re.compile(r"(\.\./|\.\.\\|['\";|]|/dev/null|\$\(|`|\\\x00)")

_SENSITIVE_CLAIM_RE = re.compile(
    r"(password|passwd|secret|ssn|social_security|credit_?card|card_?number|"
    r"cvv|pin|otp|private_?key|api_?key|access_?token|refresh_?token)",
    re.IGNORECASE,
)

# exp - iat beyond this many seconds is "long-lived" for a bearer token.
LONG_LIVED_SECONDS = 30 * 24 * 3600


def check_algorithm(token):
    findings = []
    alg = token.alg
    if not alg:
        findings.append(Finding(
            check_id="alg-missing",
            severity="high",
            title="Token header has no usable 'alg'",
            detail="The header's alg is missing or not a string, so verifiers "
                   "must guess how (or whether) the token is signed.",
            remediation="Always set alg explicitly to the intended algorithm "
                        "and reject tokens whose alg does not match it.",
        ))
    elif alg.lower() == "none":
        findings.append(Finding(
            check_id="alg-none",
            severity="critical",
            title="Token uses alg=none (unsigned)",
            detail="alg=none means the token carries no signature at all. Any "
                   "verifier that accepts it will trust attacker-written claims.",
            remediation="Never issue or accept alg=none tokens outside a "
                        "closed test environment; pin the expected algorithm "
                        "on the verifier.",
        ))
    if alg.lower() != "none" and not token.signature:
        findings.append(Finding(
            check_id="empty-signature",
            severity="high",
            title="Signature segment is empty",
            detail=f"alg is {alg or '<missing>'} but the signature segment is "
                   "empty, so the token is effectively unsigned.",
            remediation="Reject tokens with an empty signature whenever alg "
                        "is not 'none', and never issue them.",
        ))
    return findings


def check_weak_secret(token, extra_secrets=()):
    if not is_hmac_alg(token.alg):
        return []
    cracked = find_weak_secret(token, extra_secrets)
    if cracked is None:
        return []
    shown = "<empty string>" if cracked == "" else repr(cracked)
    return [Finding(
        check_id="weak-hmac-secret",
        severity="critical",
        title="HMAC secret falls to a small dictionary",
        detail=f"The {token.alg} signature verifies with the well-known "
               f"secret {shown}. Anyone can now mint tokens with arbitrary "
               "claims for this issuer.",
        remediation="Rotate the signing secret immediately to a long, random "
                    "value (32+ bytes) stored in a secret manager, and "
                    "invalidate tokens signed with the old secret.",
    )]


def check_embedded_keys(token):
    findings = []
    present = [p for p in EMBEDDED_KEY_PARAMS if p in token.header]
    if present:
        findings.append(Finding(
            check_id="embedded-key-material",
            severity="high",
            title="Token header embeds or references its own key material",
            detail="Header parameter(s) %s let the token itself supply or "
                   "point at the verification key. Verifiers that honour "
                   "them can be forced to trust an attacker-supplied key."
                   % ", ".join(present),
            remediation="Ignore jwk/jku/x5u/x5c in token headers; verify only "
                        "against keys from the issuer's trusted key set.",
        ))
    kid = token.header.get("kid")
    if isinstance(kid, str) and _KID_INJECTION_RE.search(kid):
        findings.append(Finding(
            check_id="kid-injection-pattern",
            severity="medium",
            title="kid header looks injectable",
            detail=f"kid value {kid!r} contains traversal or injection "
                   "metacharacters. kid is commonly used in file paths, SQL "
                   "queries or shell commands during key lookup.",
            remediation="Treat kid as an opaque identifier: look it up in a "
                        "fixed key map, never interpolate it into paths, "
                        "queries or commands.",
        ))
    return findings


def check_duplicate_keys(token):
    findings = []
    for where, dups in (("header", token.header_duplicates),
                        ("payload", token.payload_duplicates)):
        if dups:
            findings.append(Finding(
                check_id="duplicate-json-keys",
                severity="medium",
                title=f"Duplicate keys in the token {where}",
                detail="Key(s) %s appear more than once in the %s. Different "
                       "JSON parsers resolve duplicates differently, so a "
                       "verifier and the application can disagree about the "
                       "token's contents." % (", ".join(dups), where),
                remediation="Reject tokens containing duplicate JSON keys; "
                            "issue tokens with a canonical serializer.",
            ))
    return findings


def _numeric_claim(payload, name):
    value = payload.get(name)
    if isinstance(value, bool):  # bool is an int subclass; not a timestamp
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def check_lifetime(token, now=None):
    findings = []
    now = time.time() if now is None else float(now)
    payload = token.payload
    exp = _numeric_claim(payload, "exp")
    iat = _numeric_claim(payload, "iat")
    nbf = _numeric_claim(payload, "nbf")

    if exp is None:
        findings.append(Finding(
            check_id="missing-expiry",
            severity="medium",
            title="Token has no exp (expiry) claim",
            detail="Without exp, the token never expires on its own; a leaked "
                   "copy stays valid until the signing key rotates.",
            remediation="Always issue tokens with a short exp and enforce it "
                        "on the verifier.",
        ))
    else:
        if exp <= now:
            findings.append(Finding(
                check_id="token-expired",
                severity="low",
                title="Token is already expired",
                detail="exp is in the past. The finding matters only if a "
                       "verifier still accepts the token.",
                remediation="Ensure verifiers reject expired tokens "
                            "(exp must be enforced, with small clock skew).",
            ))
        lifetime = (exp - iat) if iat is not None else None
        if lifetime is not None and lifetime > LONG_LIVED_SECONDS:
            findings.append(Finding(
                check_id="long-lived-token",
                severity="medium",
                title="Token lifetime is very long",
                detail=f"exp - iat is {lifetime / 86400:.0f} days. Long-lived "
                       "bearer tokens widen the window for replay after theft.",
                remediation="Shorten access-token lifetimes (minutes to "
                            "hours) and use refresh-token rotation for "
                            "longer sessions.",
            ))
        elif iat is None and exp - now > LONG_LIVED_SECONDS:
            findings.append(Finding(
                check_id="long-lived-token",
                severity="medium",
                title="Token stays valid far into the future",
                detail=f"exp is {(exp - now) / 86400:.0f} days in the future "
                       "and there is no iat to bound the lifetime.",
                remediation="Add iat and shorten exp; long validity windows "
                            "make leaked tokens durable.",
            ))
    if nbf is not None and nbf > now:
        findings.append(Finding(
            check_id="token-not-yet-valid",
            severity="info",
            title="Token is not valid yet (nbf in the future)",
            detail="nbf lies ahead of the current time; the token should "
                   "currently be rejected by verifiers.",
            remediation="No action needed unless verifiers accept the token "
                        "before nbf.",
        ))
    return findings


def check_sensitive_claims(token):
    findings = []
    hits = [k for k in token.payload if _SENSITIVE_CLAIM_RE.search(str(k))]
    if hits:
        findings.append(Finding(
            check_id="sensitive-claims",
            severity="medium",
            title="Payload carries sensitive-looking claims",
            detail="Claim name(s) %s look like credentials or regulated "
                   "personal data. A JWT payload is only base64-encoded -- "
                   "anyone holding the token can read them."
                   % ", ".join(sorted(hits)),
            remediation="Never put passwords, tokens, card data or government "
                        "IDs in a JWT payload; keep only the identifiers the "
                        "verifier needs.",
        ))
    return findings


def audit_token(token, extra_secrets=(), now=None):
    """Run every check against a decoded token."""
    findings = []
    findings += check_algorithm(token)
    findings += check_weak_secret(token, extra_secrets)
    findings += check_embedded_keys(token)
    findings += check_duplicate_keys(token)
    findings += check_lifetime(token, now=now)
    findings += check_sensitive_claims(token)
    return findings
