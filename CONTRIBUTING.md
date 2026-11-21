# Contributing to jwt-auditor

Thanks for helping! `jwt-auditor` decodes a JSON Web Token and audits
it for the weaknesses that actually get exploited — `alg=none`, weak
HMAC secrets, embedded key material, injectable `kid` values, parser
differentials, lifetime and claim hygiene — and produces a prioritised
report with a 0–100 risk score.

It is a **defensive, authorised-testing tool**. The most valuable
contributions are new checks, weak-secret dictionary additions backed
by real-world defaults, example tokens, and tests.

## Ground rules

- **Fully offline — hard rule.** jwt-auditor makes no network calls,
  and never will. No telemetry, no lookups, nothing.
- **Zero runtime dependencies — hard rule.** Python standard library
  only (the HMAC dictionary check is `hashlib`/`hmac`, decoding is
  `base64`/`json`).
- **Audit, don't exploit.** The tool reports exposure and the fix. It
  does not implement forging attacks (e.g. RS256→HS256 confusion
  token crafting) and contributions must not add exploitation
  features. Testing the signature against a dictionary of *known weak*
  secrets is the one deliberate exception — it proves a secret is
  public knowledge.
- **Only audit tokens you are authorised to test.** A cracked signing
  secret is a critical finding: it goes to the system owner, gets
  rotated, and is never used beyond the authorisation.

## Development setup

Requires Python 3.9 or newer.

```bash
git clone https://github.com/gravion-ux/jwt-auditor.git
cd jwt-auditor
pip install -e ".[dev]"
```

The package uses a `src/` layout (`src/jwt_auditor/`); the root
`conftest.py` puts `src/` on the path for pytest. (CI installs with
`pip install -e . pytest pytest-cov` — equivalent.)

## Running the tests

```bash
python -m pytest -q
```

With coverage (this is what CI runs):

```bash
python -m pytest -q --cov=jwt_auditor --cov-report=xml
```

Try the bundled examples:

```bash
jwt-auditor audit --file examples/weak-secret.txt   # critical: dictionary secret
jwt-auditor audit --file examples/alg-none.txt      # critical: alg=none
jwt-auditor audit --file examples/healthy.txt       # no findings, exit 0
```

## Anatomy of a check

Checks live in `src/jwt_auditor/checks.py`. Each check is a function
taking the decoded token (plus, for the dictionary check, extra
secrets) and returning `Finding`s with a stable kebab-case `check_id`
(`alg-none`, `weak-hmac-secret`, `kid-injection-pattern`, …), a
severity, a plain-language detail, and a concrete remediation.
`audit_token()` runs every check — wire new checks in there.

To add a check:

1. Implement it in `checks.py` and register it in `audit_token()`.
2. Add tests in `tests/test_checks.py`. The test module has `mint()`
   and `healthy_payload()` helpers — build tokens with them instead
   of pasting opaque strings, so the test shows exactly what is
   being audited. Lifetime tests use the fixed `NOW` constant; keep
   tests deterministic.
3. If the check deserves a demo, add an example token under
   `examples/` and mention it in the README.

Weak-secret additions go in `BUILTIN_SECRETS` in
`src/jwt_auditor/secrets.py`. The list is deliberately small — the
secrets that recur in tutorials, framework defaults and leaked code.
Only add a secret you can point to as a real recurring default, and
add a test that mints a token with it and expects
`weak-hmac-secret`.

## Code style

- Module docstring at the top; `from __future__ import annotations`;
  type hints; double quotes.
- Comments explain *why* a threshold or pattern exists (e.g. why
  30 days counts as long-lived).
- Tests are plain pytest functions with descriptive names.

## Proposing a bigger change

New report formats, scoring changes, or anything that changes
existing `check_id`s/severities: **open an issue first**. New checks,
dictionary entries and examples can go straight to a pull request.

## Pull request workflow

1. Fork and branch from `main`: `check/<check-id>` for new checks,
   `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`
   otherwise.
2. Run the full suite locally and audit the three bundled examples.
3. Open the PR against `main` with: what changed, why, how you
   tested it — and for dictionary entries, where the secret recurs
   (tutorial, framework default, leaked config).
4. CI must be green — Python 3.10, 3.11 and 3.12 plus the CLI smoke
   test.
5. One logical change per PR.
