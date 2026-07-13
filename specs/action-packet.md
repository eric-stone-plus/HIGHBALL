# Action Packet

> The Action Packet is the portable evidence bundle for a proposed action. It
> records why a route was selected, what trace was evaluated, and whether the
> action can cross its boundary.

Implementation status: the existing v1 schema, builder, and validator encode a
retired per-phase QUINTE ledger shape. They remain available only for archived
packet compatibility. New integrations bind an atomic QUINTE product outcome;
they must not use the v1 fields to dispatch, retry, or supervise QUINTE.

## 1. Purpose

Residual traces are claim artifacts. Route decisions are path artifacts.
Quality metrics are measurement artifacts. Dispatch evidence is execution
evidence. Authorization is a boundary artifact.

An Action Packet binds them for one proposed action so a later operator cannot
reuse a verdict, route decision, or metric outside its original scope.

## 2. Packet Fields

```json
{
  "packet_version": "1.0",
  "route_request": {},
  "route_decision": {},
  "trace": {},
  "validation": {},
  "quality": {},
  "execution_evidence": {},
  "action_decision": "review",
  "decision_reasons": ["string"],
  "required_next_steps": ["string"]
}
```

`route_request` follows `specs/residual-routing.md`. `trace` follows RASHOMON
`schemas/residual-trace.schema.json`. `quality` follows RASHOMON
`specs/residual-quality-metrics.md`, including trial-manifest metrics when the
trace declares perturbation conditions.
`execution_evidence` records whether the selected route requires product-level
execution proof. When QUINTE is selected, it binds the atomic CLI outcome. The
packet does not summarize or validate QUINTE's internal phase, lane, agent,
retry, pacing, or artifact state.

`schemas/action-packet.schema.json` and `bin/validate-action-packet.py` are the
legacy v1 compatibility implementation. They are not an active QUINTE control
surface.

## 3. Decision Rule

The Action Packet is conservative:

1. Structural validation errors set `action_decision` to `block`.
2. Validator block findings set `action_decision` to `block`.
3. Route `block` sets `action_decision` to `block`.
4. Required QUINTE product outcome that is missing, invalid, blocked, or
   degraded sets `action_decision` to `block`.
5. Quality gate `block` sets `action_decision` to `block`.
6. Route and trace instrument mismatch sets `action_decision` to `review`,
   unless a stricter block already applies.
7. Route request and trace action-boundary mismatch sets `review`, unless a
   stricter block already applies.
8. Missing KENGEN authorization sets `review` for actions that require KENGEN.
9. Quality gate `review` sets `review` unless a block applies.
10. Otherwise the packet may pass.

`pass` means the packet has enough evidence for the selected boundary. It does
not authorize `git push`, deletion, credential mutation, deployment, legal
commitment, or money movement. KENGEN still owns authorization.

## 4. Route And Trace Compatibility

- `direct-evidence` is compatible with `trace.instrument: direct-evidence`.
- `MAGI` is compatible with `trace.instrument: MAGI`.
- `QUINTE` is compatible with `trace.instrument: QUINTE`.
- `human-review` is compatible with `trace.instrument: human`.
- `block` is compatible with any trace that records the block condition.

Mismatch does not always mean the work is invalid. It means the packet cannot
prove that the selected route produced the supplied trace.

For QUINTE, compatibility also requires a completed atomic product outcome. If
that outcome is missing, blocked, degraded, or invalid, the Action Packet
blocks. HIGHBALL does not look through the outcome to judge phase completion or
retry behavior; those are QUINTE scheduler invariants. This prevents a residual
trace from laundering an unsuccessful product invocation into protected-write
evidence without creating a second scheduler.

When multiple Action Packets accumulate for a route group, HIGHBALL can
summarize their execution reliability with
`specs/residual-route-execution.md`. That route-level report feeds policy
review; it does not change the decision for the original packet.

The route request and trace must also cover the same action boundary. A
boundary mismatch is a review condition because the trace may be valid evidence
for a different boundary while failing to cover the proposed action.

## 5. Validator Exit Codes

`bin/validate-action-packet.py` exits with:

- `0`: packet is structurally valid and its action decision is `pass` or `review`.
- `1`: packet is structurally valid and its action decision is `block`.
- `2`: packet is malformed or inconsistent with derived route, validation, quality, or decision values.

## 6. Non-Goals

Action Packet does not:

- dispatch agents
- mutate files
- authorize push or irreversible operations
- prove truth
- rewrite earlier outputs

It packages route, trace, validation, measurement, and boundary decision into a
single reviewable artifact.
