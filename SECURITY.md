# Security Policy

`jwt-auditor` is a security tool, and it is fully offline by design —
it makes no network calls, ever. This policy covers vulnerabilities
**in this repository**: the auditor itself.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it
privately, either way:

- GitHub's private vulnerability reporting:
  <https://github.com/gravion-ux/jwt-auditor/security/advisories/new>
- Email: priyanshukumarthakur937@gmail.com

Please include:

- A one- or two-sentence description of the issue.
- The version or commit SHA it affects.
- The smallest reproduction you have — an example token that triggers
  it is ideal (use a token you minted for testing, never a real
  production token).
- The impact you believe it has.

You can expect an acknowledgement within a few days.

## Disclosure timing

Please allow **90 days** for a fix to be released before any public
disclosure. If a fix ships earlier, coordinated disclosure can happen
as soon as the fixed version is available.

## Scope

In scope — the auditor itself, for example:

- A crafted token that crashes the auditor, hangs it (parser denial
  of service), or makes it silently skip a check it should have run —
  e.g. a token with a known weak secret or `alg=none` that the tool
  reports as clean.
- Any network activity by the tool, for any reason. There should be
  none; a packet capture showing otherwise is a vulnerability report.
- Report output that executes or embeds unescaped content from a
  token in a way that endangers whoever reads the report.

Out of scope:

- Weaknesses jwt-auditor *finds* in your tokens. That is the tool
  working. A cracked signing secret is a critical finding: report it
  to the system owner, rotate the secret, and never use it beyond
  your authorisation.
- Requests to add exploitation features (token forging, confusion
  attacks). The tool audits; it does not exploit, by design.

## Supported versions

Only the current `main` branch and the latest release are supported.
Older commits are kept for history, not for backports.
