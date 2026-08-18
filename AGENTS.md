# AGENTS.md — HIGHBALL contributor rules

HIGHBALL is a public deterministic control plane. Committed work must remain
English, reproducible on a clean checkout, and free of credentials, personal
machine paths, private endpoints, or host-specific deployment details.

## Contribution rules

- Preserve fail-closed routing, authorization, and protected-write semantics.
- Keep product boundaries explicit: HIGHBALL validates opaque QUINTE
  products; it does not absorb their internal runtime.
- New behavior requires tests, and `scripts/check-local.sh` must pass before a
  push.
- Preserve contributor identity. Agent-authored commits use the agent's
  GitHub-linked Git author identity rather than the human operator or only a
  co-author trailer; human-authored commits retain the human author.
