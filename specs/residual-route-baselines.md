# Residual Route Baselines

> Baseline comparison asks whether a route earned its cost against a cheaper or
> stronger evidence path. It does not prove truth and does not authorize action.

## 1. Purpose

Route calibration can say that QUINTE, MAGI, direct evidence, or human review
produced useful residual traces. That is not enough. A route can be useful and
still be worse than a cheaper or stronger baseline for the same action boundary.

Baseline comparison is the engineering answer to that problem. It compares a
target route group against a baseline route group with the same action boundary,
using calibrated residual quality and optional outcome feedback.

## 2. Inputs

`bin/build-route-baseline-report.py` consumes a validated route calibration
report, optional follow-up outcome ledger, target route group, and optional
baseline route group. The baseline should be cheaper, stronger, or more direct
for the same action boundary.

If no baseline route group is supplied, the builder chooses a same-boundary
candidate by preferring non-blocked direct evidence, human review,
heterogeneous review, mixed review, same-family review, same-model review, then
unknown routes.

The schema is `schemas/route-baseline-report.schema.json`. The independent
validator is `bin/validate-route-baseline-report.py`; it recomputes deltas,
verdicts, reasons, and summary counts.

Use `bin/validate-evidence-chain.py` when a baseline report will support a
policy or protocol change. It verifies that embedded target and baseline
summaries still match the referenced calibration report, and that outcome
summaries still match the referenced outcome ledger.

Use `specs/residual-route-experiments.md` when the baseline comparison is part
of a planned route evaluation. The experiment review checks that the required
baseline was declared before the result was interpreted.

## 3. Verdicts

- `target_preferred`: the target route outperformed the baseline on calibrated evidence or outcome weakness affects the baseline.
- `baseline_preferred`: the baseline outperformed the target or target outcomes weaken the route.
- `target_blocked`: the target route group is blocked by calibration.
- `watch`: signals are mixed or too close to justify a route preference.
- `insufficient`: the comparison lacks a baseline, trace cohort, or required metrics.

Summary recommendation maps verdict counts into `prefer_target`,
`prefer_baseline`, `block_target`, `watch`, or `insufficient`.

## 4. Same-Model QUINTE Use

Same-model QUINTE is allowed to win only by evidence. It must show inspectable
residual yield, closure strength, acceptable risk, and cost-normalized value
against at least one baseline. A same-model target that is blocked, expensive
without extra residual value, or weakened by later outcomes should not be
promoted into a default route.

This is the operational distinction from mixture-of-agents aggregation. The
question is not whether the group produced an attractive answer. The question
is whether the route produced better residual evidence than the alternatives.

## 5. Non-Authorization

Route baseline reports do not:

- change SHIMEI routing
- authorize protected writes, push, deletion, deployment, legal, or financial
  actions
- replace Action Packets
- replace route policy reports
- replace route experiment manifests or reviews
- turn residual scores into truth probabilities

They are review evidence for future route policy changes.
