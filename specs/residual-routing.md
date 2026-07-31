# Residual Routing

HIGHBALL chooses the next evidence product before work crosses an action
boundary. It does not decide truth.

## Routes

- `direct-evidence`: executable or source-verifiable work that does not need
  adversarial interpretation first.
- `QUINTE`: bounded, single-family adversarial review. Requires a completed
  atomic QUINTE product plus its residual trace.
- `MAGI`: high-intensity cross-family verification with a final actionable
  conclusion. Requires a completed atomic MAGI product plus its residual trace.
- `human-review`: credentials, deletion, deployment, financial, legal, waiver,
  or evidence-ceiling decisions.
- `block`: missing required evidence, invalid product identity, absent
  authorization, or open high-risk residuals at a strict boundary.

## Closed Input

```json
{
  "question": "string",
  "action_boundary": "protected_write",
  "change_class": "architecture",
  "affected_paths": ["path"],
  "action_scope": "exact product scope",
  "risk": "HIGH",
  "executable": false,
  "trace_quality_gate": "review",
  "open_high_risk_count": 0
}
```

Unknown fields are rejected. The action binding covers `question`,
`action_boundary`, `change_class`, and ordered `affected_paths`; product scope
is also compared exactly.

## Decision Order

1. Existing trace gate `block`, or open high-risk residuals at a protected or
   irreversible boundary: `block`.
2. Credential, deletion, deployment, financial, or legal action:
   `human-review`.
3. Irreversible action: `MAGI`.
4. High-risk protected write: `MAGI`.
5. Other protected write: `QUINTE`.
6. Architecture decision: `MAGI`; protocol change: `QUINTE`.
7. Executable/source-verifiable reversible work: `direct-evidence`.
8. Other low/medium judgment: `QUINTE`.
9. Other high/critical/P0 judgment: `MAGI`.

QUINTE and MAGI require a non-empty `action_scope`; otherwise routing blocks.
External authorization remains a separate boundary.

## Output

```json
{
  "route": "MAGI",
  "reason": ["string"],
  "required_artifacts": ["string"],
  "residual_trace_required": true,
  "authorization_required": false
}
```

The output is advisory until bound into Action Packet `2.0`. HIGHBALL does not
inspect or retry internal product phases and does not certify statistical
independence.
