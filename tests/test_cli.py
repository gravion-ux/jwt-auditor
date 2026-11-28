"""End-to-end CLI tests: exit codes, formats, input routes."""

import json
from pathlib import Path

import pytest

from jwt_auditor.cli import main
from jwt_auditor.decode import decode_token

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
NOW = 1_800_000_000  # fixed time within the synthetic examples' validity window


def _example(name):
    return (EXAMPLES / name).read_text(encoding="utf-8").strip()


def test_audit_weak_secret_exits_1(capsys):
    assert main(["audit", _example("weak-secret.txt")]) == 1
    out = capsys.readouterr().out
    assert "weak-hmac-secret" in out


def test_audit_alg_none_exits_1():
    assert main(["audit", _example("alg-none.txt")]) == 1


def test_audit_healthy_token_exits_0(capsys):
    # Exit 0 under the default --fail-on (high): nothing at high/critical.
    # (The static example token may be expired by the time the test runs;
    # expiry is a low finding and must not change this verdict.)
    assert main(["audit", _example("healthy.txt")]) == 0
    assert "jwt-auditor report" in capsys.readouterr().out


def test_audit_json_format(capsys):
    assert main(["audit", "--format", "json", _example("weak-secret.txt")]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "jwt-auditor"
    assert report["summary"]["critical"] >= 1
    assert report["token"]["alg"] == "HS256"


def test_audit_fail_on_threshold(capsys):
    # The weak-secret finding is critical, so it trips even --fail-on
    # critical; the healthy token has nothing at high or above, so it
    # passes the default threshold (checked in the test above).
    assert main(["audit", "--fail-on", "critical", _example("weak-secret.txt")]) == 1
    capsys.readouterr()
    assert main(["audit", "--fail-on", "info", _example("weak-secret.txt")]) == 1


def test_audit_malformed_token_exits_2(capsys):
    assert main(["audit", "not-a-jwt"]) == 2
    assert "malformed" in capsys.readouterr().err


def test_audit_from_file(tmp_path):
    path = tmp_path / "token.txt"
    path.write_text(_example("alg-none.txt"), encoding="utf-8")
    assert main(["audit", "--file", str(path)]) == 1


@pytest.mark.parametrize(("name", "check_id"), [
    ("kid-injection.txt", "kid-injection-pattern"),
    ("duplicate-keys.txt", "duplicate-json-keys"),
])
@pytest.mark.parametrize(("fail_on", "exit_code"), [("high", 0), ("medium", 1)])
def test_audit_synthetic_examples_json(
    name, check_id, fail_on, exit_code, monkeypatch, capsys,
):
    monkeypatch.setattr("jwt_auditor.checks.time.time", lambda: NOW)

    assert main([
        "audit", "--file", str(EXAMPLES / name), "--format", "json",
        "--fail-on", fail_on,
    ]) == exit_code

    report = json.loads(capsys.readouterr().out)
    assert [finding["check_id"] for finding in report["findings"]] == [check_id]
    assert report["findings"][0]["severity"] == "medium"
    assert report["summary"]["medium"] == 1
    assert report["risk_score"] == 7


@pytest.mark.parametrize(("name", "check_id"), [
    ("kid-injection.txt", "kid-injection-pattern"),
    ("duplicate-keys.txt", "duplicate-json-keys"),
])
def test_audit_synthetic_examples_markdown(name, check_id, monkeypatch, capsys):
    monkeypatch.setattr("jwt_auditor.checks.time.time", lambda: NOW)

    assert main(["audit", "--file", str(EXAMPLES / name)]) == 0

    output = capsys.readouterr().out
    assert "jwt-auditor report" in output
    assert check_id in output
    assert "[MEDIUM]" in output


@pytest.mark.parametrize("name", ["kid-injection.txt", "duplicate-keys.txt"])
def test_synthetic_example_contents(name):
    token = decode_token(_example(name))
    assert token.header["alg"] == "HS256"
    assert token.payload["iss"] == "https://issuer.example.invalid"
    assert token.payload["sub"] == "synthetic-demo-user"
    assert token.payload["iat"] < NOW < token.payload["exp"]
    assert token.header_duplicates == []
    if name == "kid-injection.txt":
        assert token.header["kid"] == "../../dev/null"
        assert token.payload_duplicates == []
    else:
        assert token.payload_duplicates == ["role"]
        assert token.payload["role"] == "editor"


def test_decode_command(capsys):
    assert main(["decode", _example("healthy.txt")]) == 0
    decoded = json.loads(capsys.readouterr().out)
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["sub"] == "1234567890"
