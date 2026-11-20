"""Risk scoring and JSON / Markdown report rendering."""

import json
from datetime import datetime, timezone

from . import __version__
from .models import SEVERITY_ORDER, sort_findings

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 3,
    "info": 1,
}


def risk_score(findings):
    """0 (clean) to 100 (maximally risky), weighted by severity."""
    return min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))


def grade(score):
    if score <= 0:
        return "clean"
    if score < 25:
        return "low"
    if score < 50:
        return "moderate"
    if score < 75:
        return "high"
    return "critical"


def token_info(token):
    """Non-sensitive structural summary of the token for the report."""
    return {
        "alg": token.alg or None,
        "typ": token.header.get("typ"),
        "kid": token.header.get("kid"),
        "header_claims": sorted(token.header),
        "payload_claims": sorted(token.payload),
        "signature_bytes": len(token.signature),
    }


def build_report(token, findings):
    findings = sort_findings(findings)
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    score = risk_score(findings)
    return {
        "tool": "jwt-auditor",
        "version": __version__,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "token": token_info(token),
        "risk_score": score,
        "grade": grade(score),
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
    }


def render_json(report):
    return json.dumps(report, indent=2) + "\n"


def _md_cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(report):
    info = report["token"]
    lines = []
    lines.append("# jwt-auditor report")
    lines.append("")
    lines.append("- **Algorithm:** %s" % (info["alg"] or "<missing>"))
    lines.append("- **Generated (UTC):** %s" % report["generated_utc"])
    lines.append("- **Risk score:** %d/100 (%s)" % (report["risk_score"], report["grade"]))
    lines.append("- **Payload claims:** %s" % (", ".join(info["payload_claims"]) or "<none>"))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append("| %s | %d |" % (sev, report["summary"][sev]))
    lines.append("")
    if not report["findings"]:
        lines.append("No findings. Nothing in the audited checks fired for this token.")
        lines.append("")
        return "\n".join(lines)
    lines.append("## Findings")
    lines.append("")
    lines.append("| # | Severity | Check | Title |")
    lines.append("| --- | --- | --- | --- |")
    for i, f in enumerate(report["findings"], 1):
        lines.append("| %d | %s | %s | %s |" % (
            i, f["severity"], _md_cell(f["check_id"]), _md_cell(f["title"])))
    lines.append("")
    lines.append("## Details")
    for i, f in enumerate(report["findings"], 1):
        lines.append("")
        lines.append("### %d. [%s] %s" % (i, f["severity"].upper(), f["title"]))
        lines.append("")
        lines.append("- **Check:** `%s`" % f["check_id"])
        lines.append("- **Detail:** %s" % f["detail"])
        lines.append("- **Remediation:** %s" % f["remediation"])
    lines.append("")
    return "\n".join(lines)
