## What changed

<!-- One or two sentences. What is different after this pull request? -->

## Why

<!-- Link the issue it closes, or state the problem it solves. For a
     dictionary addition: where the secret recurs (tutorial, framework
     default, leaked config). -->

## How it was tested

<!-- The exact commands you ran and what they printed, e.g.
     `python -m pytest -q` (all passing) plus the three bundled
     examples: weak-secret (critical), alg-none (critical), healthy
     (clean, exit 0). -->

## Checklist

- [ ] Full test suite passes locally and CI is green
- [ ] Tests added or updated for the change (tokens built with the `mint()` / `healthy_payload()` helpers, not pasted opaque strings)
- [ ] No existing `check_id` renamed and no severity silently changed
- [ ] The tool still makes zero network calls and adds no runtime dependency
- [ ] No exploitation feature added (the tool audits; it does not forge or attack)
- [ ] No real production tokens or secrets anywhere in the diff
- [ ] Docs updated (README / examples) if behaviour changed
- [ ] One logical change in this PR
