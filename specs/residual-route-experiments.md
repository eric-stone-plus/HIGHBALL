# Residual Route Experiments

> Route experiments register the evaluation plan before a route cohort is
> collected. They do not authorize action, dispatch agents, or modify routing
> rules.

## 1. Purpose

Route calibration and outcome feedback are only credible when the evaluation
conditions are declared before the evidence is interpreted. Otherwise a route
can be promoted by post hoc sample selection: choose the traces that look good,
ignore the baseline that won, or move the stopping rule after a blocked run.

The route experiment layer adds two artifacts:

- A route experiment manifest records the planned route group, trace inputs,
  baseline route groups, outcome requirements, success criteria, and stopping
  rules.
- A route experiment review compares the manifest against the actual
  calibration report, baseline report, and outcome ledger.

This is the engineering answer to the academic critique that homogeneous
multi-agent debate can look persuasive while failing against cheaper
self-correction, direct evidence, or properly designed baselines.

## 2. Manifest

`bin/validate-route-experiment-manifest.py` validates a pre-run manifest. The
schema is `schemas/route-experiment-manifest.schema.json`.

Required content:

- `experiment_id`: stable identifier for the planned route experiment.
- `route_group`: target group such as `QUINTE:same_model:protected_write`.
- `planned_trace_inputs`: files, directories, or explicit route sources expected to enter calibration.
- `cohort_requirements`: minimum target trace count, minimum candidate files, and maximum invalid trace files.
- `baseline_requirements`: whether a same-boundary baseline is required and which route groups must be present.
- `pairing_requirements`: whether same-question target/baseline trace pairs are required.
- `outcome_requirements`: whether follow-up outcome entries are required.
- `success_criteria`: calibration, baseline, pairing, outcome, and metric thresholds required before policy synthesis.
- `stopping_rule`: conditions that stop promotion, such as block recommendation, baseline preference, pairing preference, outcome regression, or trace-count cap.

The manifest is not evidence that a route works. It is evidence that the
evaluation was specified before the result was known.

## 3. Review

`bin/build-route-experiment-review.py` consumes the pre-run route experiment
manifest, actual scored route calibration report, optional or required
same-boundary route baseline report, optional or required route pairing report,
and optional or required outcome ledger.

`bin/validate-route-experiment-review.py` recomputes the review from the
referenced artifacts. The schema is `schemas/route-experiment-review.schema.json`.

Review verdicts:

- `supports_policy_review`: the experiment met the manifest and may be used as evidence for route policy synthesis.
- `needs_more_evidence`: the plan was valid but sample size, metrics, baseline, pairing, or outcome evidence is still insufficient.
- `stop_blocked`: a planned stopping rule fired. Do not promote the route into keep policy.
- `plan_violation`: the observed evidence did not match the manifest or required artifacts were missing.

## 4. Policy Use

`bin/build-route-policy-report.py` accepts an optional `--experiment-review`.
When present, the review can only make policy synthesis more conservative:

- `supports_policy_review` leaves the normal calibration, baseline, and outcome
  rule intact.
- `needs_more_evidence` prevents `keep` and downgrades it to `watch`.
- `stop_blocked` yields `block`.
- `plan_violation` yields `insufficient`, unless the underlying evidence is
  already blocking.

When no experiment review is supplied, the policy report records
`not_provided`. That preserves compatibility with existing artifacts while
making the missing pre-registration visible.

## 5. Evidence Chain

`bin/validate-evidence-chain.py` accepts a route experiment review as a root
artifact. It also validates experiment-review references when a policy report
uses one. The chain checks that:

- the review is exactly recomputable from its manifest and reports
- the review route group matches the policy route group
- calibration, baseline, pairing, and outcome references match across artifacts
- baseline, pairing, and outcome subchains remain valid

## 6. Non-Authorization

Route experiment manifests and reviews do not:

- dispatch QUINTE, MAGI, direct evidence, or human review
- authorize protected writes, push, deployment, financial, legal, or deletion
  actions
- change SHIMEI bindings
- mutate route policy
- prove truth
- replace route calibration, baseline comparison, outcome ledgers, policy
  reports, or route change proposals

They make the route evaluation falsifiable enough for maintainers to decide
whether a separate policy change is worth reviewing.
