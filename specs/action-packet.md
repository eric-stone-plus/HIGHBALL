# Action Packet

The Action Packet is a closed, fail-closed evidence bundle for one proposed
action. Its contract version is independent of HIGHBALL's release version.

## Active Contract

Action Packet `1.1` binds:

- the closed route request and derived SHIMEI route;
- exactly one residual trace, its structural validation, and quality metrics;
- for a QUINTE route, one completed QUINTE Result `2.0` plus its sibling
  manifest and normalized Brief `1.1`;
- when KENGEN is required, one current user authorization artifact bound to the
  same action digest;
- the derived `pass`, `review`, or `block` decision.

An active residual trace uses Trace `1.1` and carries the same
`action_binding_sha256`; an otherwise valid trace from another task is not
reusable.

The active builder accepts only atomic product evidence. Older packet and phase
records remain visible in Git history but cannot authorize an active action.

## Action Binding

HIGHBALL computes `action_binding_sha256` from exactly these route-request
fields:

```json
{
  "question": "string",
  "action_boundary": "none | reversible | protected_write | irreversible",
  "change_class": "string",
  "affected_paths": ["string"]
}
```

The object is encoded as UTF-8 JSON with keys sorted by Unicode code point, no
insignificant whitespace, JSON string escaping, and the supplied path order
preserved. The digest is lowercase SHA-256 prefixed by `sha256:`. The request's
`action_scope` is additionally compared exactly with the QUINTE brief and
result; it is deliberately not inferred from evidence roots.

## QUINTE Product Binding

For an active QUINTE route, `--quinte-result` must refer to the standard
`result.json` in a run directory. HIGHBALL validates the complete Result `2.0`
shape and binds it to:

- sibling `manifest.json` and `input/brief.json`;
- canonical run UUID and standard run-directory name;
- completed manifest and product statuses;
- exact result and normalized brief digests recorded by the manifest;
- the trusted QUINTE runs root, active installed executable digest, and
  `quinte inspect RUN_ID --json` state;
- request question, action scope, affected paths, and action-binding digest;
- the fixed five QUINTE perspectives and accepted artifact paths.

A missing, degraded, legacy, malformed, moved, tampered, or differently scoped
product blocks. HIGHBALL does not schedule or retry QUINTE lanes.

## KENGEN

Protected action classes and irreversible boundaries require an explicit
KENGEN authorization artifact. The artifact contains a unique authorization
ID, `authorized_by: user`, `decision: authorize`, the exact action-binding
digest, and an issue/expiry window of at most eight hours.

The packet binds and validates the artifact. Immediately before the external
action, the host must run `bin/consume-kengen-authorization.py`. Its atomic
create-if-absent claim makes each authorization ID single use; an existing
claim blocks replay. Evidence, QUINTE output, and an Action Packet do not
themselves authorize an external action.

## Decision Rule

The decision is conservative:

1. Malformed traces, validator blocks, or route `block` block.
2. Missing or invalid required execution evidence blocks.
3. `highball_decision: block` or `escalate` blocks even with no residuals.
4. Route/trace instrument, question, or boundary mismatch blocks.
5. Missing, invalid, expired, mismatched, or replayed KENGEN authorization
   blocks an action that requires KENGEN.
6. Quality `block` blocks; quality `review` remains non-authorizing review.
7. Only `pass` has validator exit code zero.

`bin/validate-action-packet.py` independently recomputes the route, trace
validation, quality, product binding, authorization binding, and decision.

## Exit Codes

- `0`: valid packet with decision `pass`.
- `1`: valid packet with non-authorizing `review` or `block`.
- `2`: malformed or internally inconsistent packet.

The schema is `schemas/action-packet.schema.json`; product and digest contract
identifiers are centralized in `bin/highball-contracts.py`.
