"""jwt-auditor: a defensive security auditor for JSON Web Tokens.

Decodes JWTs and audits them for the weaknesses that show up in real
assessments: alg=none, empty signatures, HMAC secrets that fall to a small
dictionary, embedded key material (jwk/jku/x5u), kid injection patterns,
duplicate JSON keys, missing or excessive expiry, and sensitive claims.
Standard library only; fully offline.

Only audit tokens from systems you own or are authorised to test.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
