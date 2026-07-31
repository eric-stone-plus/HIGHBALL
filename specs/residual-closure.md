# Residual Closure

> Detection is not correction. HIGHBALL only treats a high-risk finding as
> operationally safe when the finding has been closed by evidence, blocked by
> policy, or explicitly waived.

## 1. Scope

Residual Closure is a protected-write check. It applies when a QUINTE or
other audit verdict is used to justify changes to public protocol or runtime
surface files, especially:

- `README*`
- `specs/**`
- `skills/**/SKILL.md`
- `lib/**`
- Hermes profile files such as `SOUL.md`, `USER.md`, `MEMORY.md`, `SKILL.md`,
  and `POSTMORTEM.md`

HIGHBALL does not re-evaluate the original finding. QUINTE, direct runtime
evidence, or a human review supplies that result. HIGHBALL checks whether the
record satisfies the configured action-boundary contract.

Route selection before closure is specified in `specs/residual-routing.md`.
The router decides which instrument should produce the evidence; closure checks
whether the resulting trace is safe enough for the boundary.
When both route and trace are available, `specs/action-packet.md` defines the
portable bundle that ties the closure decision to its original action scope.

## 2. Problem

The old protected-write check answered only whether a recent QUINTE verdict
trail existed.

That is insufficient. A verdict may contain unresolved `HIGH` or `P0` findings.
If Protected-Write Guard passes merely because the verdict exists, the system can convert
"problem detected" into "permission granted" without proving that the problem
was corrected, blocked, or waived.

The correct runtime question is whether every action-blocking finding in the
verdict is closed.

## 3. Closure States

- `open`: finding exists and no closure evidence is attached. It may not cross a protected-write boundary.
- `closed`: required correction was applied and verified by file, command, runtime output, or source evidence. It may cross within the stated scope.
- `blocked`: action was intentionally stopped because the finding remains unresolved. It may cross only for the block record itself and stated scope.
- `waived`: user or designated human reviewer explicitly accepts the risk with reason and scope. It may cross within the waiver scope.
- `not_applicable`: finding does not affect the current action boundary. It may cross within the stated scope.

A model output alone cannot set `closed`. Closure must cite external evidence
or an explicit waiver.

## 4. Residual Closure Ledger

Any verdict used as a protected-write trail should include a QUINTE-compatible
ledger entry for each `HIGH`, `CRITICAL`, `P0`, or action-blocking residual:

```json
{
  "trace_version": "1.1",
  "action_binding_sha256": "sha256:...",
  "question": "string",
  "instrument": "QUINTE",
  "residuals": [{
  "id": "RC-001",
  "severity": "HIGH",
  "type": "evidence_gap",
  "source": "round/participant/file/command",
  "finding": "string",
  "affected_paths": ["path or glob"],
  "error_signature": "literal string, regex, command, or null",
  "evidence": "file:line, command output, source, or null",
  "disposition": "unresolved",
  "required_closure": "human_review",
  "closure_state": "open",
  "closure_evidence": ["file:line, command output, source, waiver, or null"],
  "scope": "what action this closure covers"
  }],
  "action_boundary": "protected_write",
  "highball_decision": "review"
}
```

The canonical schema retains the `RASHOMON` namespace for trace-format
compatibility. The name has no routing or authorization semantics.
HIGHBALL's reusable validator is `bin/validate-residual-trace.py`.
The validator accepts both markdown verdicts with fenced JSON blocks and raw
JSON trace artifacts.
The companion measurement tool is `bin/measure-residual-trace.py`; it reports
advisory residual quality metrics without replacing Protected-Write Guard's block/pass
closure rule.
When a compatible trace includes `trial_manifest`, the measurement tool also
reports whether the run had independent first-pass artifacts, perturbation axes,
same-model or same-family correlation, contamination risks, and cost fields.
Strict-boundary traces without a manifest are structurally valid but should be
reviewed unless direct evidence or human waiver explains why perturbation
conditions are irrelevant.
Archive-level adoption can be inspected with `bin/scan-residual-archive.py`.
That scanner is read-only and should not be used to rewrite historical verdicts
for cosmetic compliance.

When historical verdicts do not contain JSON, Protected-Write Guard implementations may parse a
minimal textual form with these fields: residual id, severity, finding, state,
evidence, and scope.

The standalone shell guard currently enforces JSON ledgers when they are
present. Textual historical verdict parsing is optional compatibility work, not
the primary contract.

## 5. Protected-Write Guard Decision Rule

For protected writes, Protected-Write Guard uses this conservative rule.

PASS requires a valid verdict trail and every action-blocking ledger item must
be `closed`, `blocked`, `waived`, or `not_applicable` with closure evidence and
scope.

BLOCK applies when no verdict trail exists, when any action-blocking ledger item
is `open`, when the closure state is not one of the allowed closure states,
when `closed`, `blocked`, `waived`, or `not_applicable` lacks closure evidence
or scope, when a waiver lacks explicit user or human authorization, or when
`highball_decision: pass` conflicts with an open or unsupported high-risk
residual.

If a verdict predates the ledger format, it remains archive evidence but cannot
authorize a current protected write. Missing or unverifiable closure blocks.

## 6. Error Signatures

An `error_signature` is the smallest reproducible indicator that the problem is
still present. Examples:

- a literal stale phrase such as `6/6 consensus`
- a broken path such as `spec/` when the repo uses `specs/`
- a command such as `rg "Phase 5a" QUINTE/specs/PROTOCOL.md`
- a failing test name or command output

The signature must be narrow enough to avoid blocking unrelated historical
archives, but broad enough to catch the live target file.

## 7. Non-Goals

Residual Closure does not:

- create an additional product worker
- replace or inspect the QUINTE scheduler and verdict contract
- choose MAGI or QUINTE routes
- authorize `git push`
- establish correctness outside the cited evidence and scope
- require every low-severity note to be fixed

It only prevents a high-risk discovered issue from being laundered into
permission to modify protected public surfaces.

## 8. Rationale

Historical product runs show that detection and classification can succeed
while the affected artifact remains unchanged. That is an incomplete control
loop.

Residual Closure makes the loop explicit: discover the issue, classify it,
correct, block, or waive it, verify the closure, and only then act.

Without closure, the verdict remains evidence of a problem, not evidence of
safety.
