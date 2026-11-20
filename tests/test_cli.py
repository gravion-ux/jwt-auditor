"""End-to-end CLI tests: exit codes, formats, input routes."""

import json
from pathlib import Path

from jwt_auditor.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


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


def test_decode_command(capsys):
    assert main(["decode", _example("healthy.txt")]) == 0
    decoded = json.loads(capsys.readouterr().out)
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["sub"] == "1234567890"
