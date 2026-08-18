# Residual Trial Scoring

> Trial scoring compares residual yield against closure, manifest strength,
> risk, and cost. It does not estimate a correctness probability.

## 1. Purpose

Residual traces and trial manifests make a run inspectable. Trial scoring makes
runs comparable.

The score asks whether a route produced enough inspectable residual evidence to
justify using the same route again, escalating, or rerouting to a cheaper or
more direct baseline. A route must earn its cost by surfacing higher-quality
residuals than a declared self-correction, direct-evidence, or human-review
baseline.

## 2. Inputs

`bin/score-residual-trial.py` consumes a RASHOMON Trace `1.1` compatibility
artifact, including the
optional `trial_manifest`. It reuses `bin/measure-residual-trace.py` and derives:

- Residual Yield: how much material residual evidence was preserved.
- Closure Strength: whether action-blocking residuals have supported closure.
- Manifest Strength: whether perspectives, perturbations, independence controls, model relation, and cost are inspectable.
- Risk Penalty: open high-risk, unsupported closure, or silent-collapse risk.
- Cost Yield: residuals and action-blocking residuals per 10,000 tokens when token cost is present.

## 3. Output

The tool emits:

- `evidence_score`: bounded route score in `[0, 1]`; not a calibrated
  correctness probability.
- `recommendation`: `adopt`, `review`, `reroute`, or `block`.
- `residual_yield`: residual-yield component.
- `closure_strength`: closure component.
- `manifest_strength`: trial-condition component.
- `risk_penalty`: risk penalty component.
- `residuals_per_10k_tokens`: cost-normalized residual yield when token cost is known.
- `action_blocking_per_10k_tokens`: cost-normalized action-blocking residual yield when token cost is known.
- `caveats`: human-readable caveats that prevent overclaiming.

## 4. Interpretation

- `adopt`: the route produced strong, closed, inspectable residual evidence and can remain in use for similar boundaries.
- `review`: the route produced useful evidence but has same-model, manifest, closure, or other caveats.
- `reroute`: the route produced too little inspectable evidence for its boundary; use direct evidence, stronger QUINTE, human review, or a cheaper baseline.
- `block`: the trace itself contains blocking risk.

Same-model and same-family runs can score well enough for review, but they
remain stability evidence rather than independent confirmation. The score does
not convert same-model agreement into a correctness claim.

## 5. Non-Goals

Trial scoring does not:

- establish correctness beyond the referenced evidence
- authorize action
- replace Protected-Write Guard or Authorization Gate
- compare semantic answer quality
- reward high residual count without evidence or closure
- treat an expensive route as better merely because it used more workers

It is a calibration tool for deciding whether the route was worth the cost.

## 6. Baseline Obligation

Same-model QUINTE, self-refinement, and direct verification are different
evidence routes. A scored residual trial is incomplete for
route-policy use unless the cohort can eventually compare it against at least
one cheaper or stronger baseline for the same action boundary:

- isolated self-correction or self-refinement
- direct command, test, runtime, or source verification
- human review with scoped waiver or closure
- heterogeneous model review when available

This is especially important for single-base-model QUINTE. It may expose
behavioral residuals that a one-shot answer hides, but its value must be earned
by observed residual yield, closure strength, cost, and later outcome evidence.

HIGHBALL implements route-level baseline comparison in
`specs/residual-route-baselines.md`.

## 7. Cohort Calibration

Single-trace scores become more useful when aggregated over a cohort. HIGHBALL
implements cohort-level route calibration in
`bin/calibrate-residual-routes.py`, specified in
`specs/residual-route-calibration.md`.

Route calibration groups scored traces by instrument, base-model relation, and
action boundary. This keeps same-model perturbation evidence separate from
heterogeneous review and direct evidence, and it surfaces malformed trace
candidates rather than treating them as missing data.

Calibration reports are portable artifacts. Validate them with
`bin/validate-route-calibration-report.py` before using them as route-policy
evidence.

## 8. Outcome Feedback

Trial scores and route calibration reports are evidence proxies until observed
outcomes accumulate. When a later command, test, runtime observation, source
check, human review, or external signal confirms or contradicts what the trace
implied, record it in a residual outcome ledger.

Outcome ledgers are specified in `specs/residual-outcome-ledger.md`. They
provide empirical feedback for future route policy without converting the score
into a calibrated correctness probability.
