"""Command-line interface for jwt-auditor.

Subcommands:
  audit   Audit a JWT for known weakness patterns.
  decode  Decode a JWT and print its header/payload (no auditing).

Exit codes:
  0  no findings at or above the --fail-on severity
  1  findings at or above the --fail-on severity (CI should fail)
  2  usage / input error (including a malformed token)
"""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import audit_token
from .decode import TokenError, decode_token
from .models import SEVERITIES, meets_threshold
from .report import build_report, render_json, render_markdown
from .secrets import load_wordlist

AUTHORIZED_USE_NOTICE = (
    "jwt-auditor is a defensive auditing tool. Only audit tokens from "
    "systems you own or are explicitly authorised to test."
)


def _read_token(args):
    if getattr(args, "file", None):
        return Path(args.file).read_text(encoding="utf-8-sig")
    if args.token == "-":
        return sys.stdin.read()
    return args.token


def _emit(report, fmt, output):
    text = render_json(report) if fmt == "json" else render_markdown(report)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print("jwt-auditor: wrote %s report to %s (risk score %d/100, %s)"
              % (fmt, output, report["risk_score"], report["grade"]))
    else:
        sys.stdout.write(text)


def cmd_decode(args):
    token = decode_token(_read_token(args))
    print(json.dumps(
        {"header": token.header, "payload": token.payload,
         "signature_bytes": len(token.signature)},
        indent=2,
    ))
    return 0


def cmd_audit(args):
    token = decode_token(_read_token(args))
    extra_secrets = load_wordlist(args.wordlist) if args.wordlist else ()
    findings = audit_token(token, extra_secrets=extra_secrets)
    report = build_report(token, findings)
    _emit(report, args.format, args.output)
    return 1 if any(meets_threshold(f, args.fail_on) for f in findings) else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="jwt-auditor",
        description="Defensive security auditor for JSON Web Tokens. "
                    + AUTHORIZED_USE_NOTICE,
    )
    parser.add_argument("--version", action="version",
                        version="jwt-auditor %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_token_args(p):
        p.add_argument("token", nargs="?", default=None,
                       help="The JWT string, or '-' to read it from stdin.")
        p.add_argument("--file", help="Read the token from this file instead.")

    p_audit = sub.add_parser("audit", help="Audit a JWT for weaknesses.")
    add_token_args(p_audit)
    p_audit.add_argument("--format", choices=("markdown", "json"),
                         default="markdown", help="Report format (default: markdown).")
    p_audit.add_argument("--output", help="Write the report to this file instead of stdout.")
    p_audit.add_argument("--fail-on", choices=SEVERITIES, default="high",
                         help="Exit 1 if any finding is at or above this severity "
                              "(default: %(default)s).")
    p_audit.add_argument("--wordlist",
                         help="Extra candidate HMAC secrets, one per line, "
                              "added to the built-in weak-secret dictionary.")
    p_audit.set_defaults(func=cmd_audit)

    p_decode = sub.add_parser("decode", help="Decode a JWT without auditing it.")
    add_token_args(p_decode)
    p_decode.set_defaults(func=cmd_decode)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "token", None) is None and not getattr(args, "file", None):
        parser.error("provide a token argument (or '-' for stdin, or --file)")
    try:
        return args.func(args)
    except TokenError as exc:
        print("jwt-auditor: error: malformed token: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("jwt-auditor: error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
