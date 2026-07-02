# Residual Route Pairing

> Route pairing compares target and baseline traces for the same question and
> action boundary. It does not dispatch agents, judge answers, or authorize
> action.

## 1. Purpose

Route baselines compare calibrated route groups. Route pairing is narrower: it
pairs one target trace with one baseline trace for the same question, then
computes residual-metric deltas from the existing trace scorer.

This matters for QUINTE because same-model adversarial residual exposure is not
independent model aggregation. A QUINTE trace may reveal useful residuals, but
it still has to beat direct evidence, human review, MAGI, or other same-boundary
routes on the evidence it actually produced.

The pairing layer deliberately avoids LLM-as-judge voting. Pairwise preference
judges are vulnerable to position bias, non-transitivity, and comparative
framing effects. HIGHBALL pairing instead uses the existing residual trace
schema, scorer, and evidence-chain validation.

## 2. Pair Manifest

`bin/validate-route-pair-manifest.py` validates the planned pairs before a
pairing report is built. The schema is
`schemas/route-pair-manifest.schema.json`.

Required content:

- `experiment_id`: the planned route experiment the pairs belong to.
- `route_group`: the target route group, such as `QUINTE:same_model:protected_write`.
- `baseline_route_group`: the same-boundary baseline route group.
- `action_boundary`: the shared action boundary.
- `minimum_pair_count`: the minimum number of valid same-question pairs.
- `pairs`: pair records with id, question, target trace reference, and baseline trace reference.

The manifest is not evidence that a route works. It is evidence that the pair
selection was declared before interpreting the report.

## 3. Pairing Report

`bin/build-route-pairing-report.py` consumes the pair manifest and validates
each referenced trace. For every pair it checks:

- target and baseline trace refs are local files
- both traces validate as residual traces
- both traces answer the manifest pair question
- both traces share the manifest action boundary
- the target trace belongs to the manifest target route group
- the baseline trace belongs to the manifest baseline route group

The builder scores each trace with `bin/score-residual-trial.py`, computes
metric deltas, and emits a pairing report. The schema is
`schemas/route-pairing-report.schema.json`. The validator is
`bin/validate-route-pairing-report.py`, which recomputes the report from the
manifest and traces.

## 4. Verdicts

Pair verdicts:

- `target_preferred`: the target trace has enough evidence-score or residual-yield advantage without unacceptable risk.
- `baseline_preferred`: the baseline trace outperforms the target, or the target has lower residual yield without compensating score gain.
- `target_blocked`: the target trace is blocked by its quality gate.
- `baseline_blocked`: the baseline trace is blocked by its quality gate.
- `watch`: signals are mixed or too close.
- `invalid`: pair constraints failed.

Report recommendations map pair verdict counts into `prefer_target`,
`prefer_baseline`, `block_target`, `block_baseline`, `watch`, or
`insufficient`.

`prefer_baseline` and `block_target` are conservative outcomes. The standalone
pairing validator returns exit status 1 for those valid recommendations so CI
can distinguish “valid but blocks promotion” from malformed evidence.

## 5. Experiment Use

Route experiment manifests can require pairing evidence through
`pairing_requirements`. Route experiment reviews then check:

- the planned pair manifest was used
- the pairing report belongs to the same experiment id
- the target route group matches the experiment target
- the action boundary matches
- the minimum valid pair count was met
- the pairing recommendation is allowed by the pre-run success criteria
- `stop_on_pairing_preference` blocks promotion when the baseline wins

## 6. Evidence Chain

`bin/validate-evidence-chain.py` accepts a route pairing report as a root
artifact. It also validates pairing subchains when an experiment review uses a
pairing report, and when a policy report uses that experiment review.

The chain verifies that the report is exactly recomputable from the pair
manifest and traces, and that the pairing report has not been softened inside
the experiment review.

## 7. Non-Authorization

Route pairing reports do not:

- dispatch QUINTE, MAGI, direct evidence, or human review
- authorize protected writes, push, deployment, legal, financial, or deletion actions
- modify SHIMEI routing
- promote a route policy
- prove truth
- replace route calibration, baseline comparison, outcome ledgers, experiment reviews, policy reports, or route change proposals

They make same-question route comparisons inspectable enough for later
experiment and policy review.
