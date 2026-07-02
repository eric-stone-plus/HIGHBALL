# Residual Routing

> HIGHBALL decides the next operational route. It does not decide truth.

## 1. Purpose

Residual routing answers one question before work crosses an action boundary:
which instrument must produce or close the residual trace?

The route is derived from boundary, reversibility, executable evidence,
protected paths, risk, and existing trace quality. It is not selected by
preference, convenience, or historical tool identity.

## 2. Routes

- `direct-evidence`: use when the claim is executable or source-verifiable and does not need adversarial interpretation first. Required artifact: file, command, runtime, source, or user evidence trace.
- `MAGI`: use when the claim is reversible or low/medium risk and benefits from independent convergence/divergence review. Required artifact: RASHOMON-compatible convergence/divergence residual trace.
- `QUINTE`: use when the claim may affect public protocol, protected writes,
  irreversible action, architecture, legal/financial exposure, or high-risk
  unresolved residuals. Required artifacts: RASHOMON-compatible adversarial
  residual trace with R3 closure ledger, plus complete R1/R2/R3 QUINTE
  dispatch ledgers.
- `human-review`: use when machine routes reach their ceiling, evidence is unavailable, or a waiver/block decision is required. Required artifact: scoped human decision, waiver, block record, or explicit evidence.
- `block`: use when authorization is missing, a protected action conflicts with open high-risk residuals, or no valid route can produce required evidence. Required artifact: block trace or guard output.

## 3. Decision Inputs

The routing decision is based on a narrow JSON request:

```json
{
  "question": "string",
  "action_boundary": "protected_write",
  "change_class": "protocol",
  "affected_paths": ["path or glob"],
  "executable": true,
  "risk": "HIGH",
  "trace_quality_gate": "review",
  "open_high_risk_count": 0,
  "user_authorized_push": false
}
```

Additional host fields may be present, but the route must be explainable using
these inputs.

## 4. Decision Rules

1. If `trace_quality_gate` is `block`, route `block`.
2. If `open_high_risk_count` is greater than zero and the boundary is
   `protected_write` or `irreversible`, route `block`.
3. If `change_class` is `credential`, `deletion`, `deployment`, `financial`, or
   `legal`, route `human-review` unless a stricter block is already triggered.
4. If `action_boundary` is `irreversible`, route `QUINTE`.
5. If `action_boundary` is `protected_write`, route `QUINTE`.
6. If `change_class` is `protocol` or `architecture`, route `QUINTE`.
7. If the claim is executable and boundary is `none` or `reversible`, route
   `direct-evidence`.
8. If risk is `LOW` or `MEDIUM`, route `MAGI`.
9. If risk is `HIGH`, `CRITICAL`, or `P0`, route `QUINTE`.
10. Otherwise route `MAGI` for independent stability review.

`git push` remains separately gated by KENGEN. A route decision may say that
QUINTE evidence is required before proposing a push, but it cannot authorize
the push.

## 5. Output

The router emits a machine-readable decision:

```json
{
  "route": "QUINTE",
  "reason": ["string"],
  "required_artifacts": ["string"],
  "residual_trace_required": true,
  "kengen_authorization_required": false
}
```

The output is advisory until enforced by the host runtime. BANNIN remains the
protected-write guard, and KENGEN remains the authorization perimeter.
When a concrete trace is available, the route decision should be bound into an
Action Packet as specified in `specs/action-packet.md`. For QUINTE, that packet
must also bind the complete phase dispatch ledgers so a trace cannot stand in
for an incomplete debate.

## 6. Non-Goals

Residual routing does not:

- dispatch agents
- choose concrete CLI commands
- certify model heterogeneity
- close residuals
- authorize push, deletion, credential mutation, deployment, or money movement
- rewrite historical debate archives

It only selects the next evidence route and records why that route is required.
