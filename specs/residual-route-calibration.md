# Residual Route Calibration

> Route calibration compares trace cohorts. It does not prove truth, authorize
> action, or aggregate answers.

## 1. Purpose

Residual trial scoring evaluates one trace or a small trace bundle. Route
calibration evaluates whether a route should remain the default for similar
future work.

This is the operational answer to the multi-agent debate literature: fixed
debate pipelines can waste tokens, amplify correlated errors, or hide invalid
artifacts. A route earns continued use only when cohorts show inspectable
residual yield, supported closure, clear trial conditions, and acceptable cost.

## 2. Inputs

`bin/calibrate-residual-routes.py` accepts residual trace files or directories.
It scans `.json` and `.md` files, extracts RASHOMON residual traces, validates
candidate traces, scores valid traces with `bin/score-residual-trial.py`, and
emits a portable calibration report. The report schema is
`schemas/route-calibration-report.schema.json`; the independent validator is
`bin/validate-route-calibration-report.py`.

The report groups valid traces by:

- `instrument`: producing route, such as `MAGI`, `QUINTE`, `direct-evidence`, or `human`.
- `base_model_relation`: trial-manifest relation, such as `same_model`, `same_family`, `heterogeneous_models`, `mixed`, `human`, `direct_evidence`, or `unknown`.
- `action_boundary`: boundary the trace claims to cover.

Earlier outputs are valid inputs, but calibration should not rewrite them.
Invalid or malformed trace candidates are reported as audit findings instead of
being silently ignored.

## 3. Output

The calibrator emits a JSON report:

- `scanned_files`: files considered by the scanner.
- `candidate_files`: files containing a residual-trace candidate.
- `trace_files`: files with at least one valid scored trace.
- `invalid_trace_files`: candidate files with at least one trace block that failed validation or JSON parsing.
- `ignored_files`: files without a residual-trace candidate.
- `trace_count`: valid scored traces.
- `recommendation`: overall route recommendation, one of `adopt`, `review`, `reroute`, `block`, or `no_data`.
- `invalid_files`: source files and reasons for invalid candidates.
- `route_groups`: per-route cohort summaries.

Each route group reports mean evidence score, residual yield, closure strength,
manifest strength, risk penalty, cost-normalized residual yield, recommendation
counts, quality-gate counts, caveats, and source files.

The file counts are audit counts, not exclusive buckets. A markdown file may
count as both `trace_files` and `invalid_trace_files` when it contains one valid
trace block and one malformed trace block.

`bin/validate-route-calibration-report.py` validates report shape and
cross-checks derived invariants:

- `candidate_files + ignored_files == scanned_files`: file accounting must close.
- `invalid_trace_files == len(invalid_files)`: malformed candidates must remain visible.
- Route-group trace totals equal top-level `trace_count`: cohort counts must not drift.
- Per-group recommendation and quality counts sum to group trace count: group summaries must be internally consistent.
- Top-level recommendation matches group recommendations and invalid files: a report cannot be softened after generation.

## 4. Interpretation

- `adopt`: cohort evidence supports keeping the route for similar future boundaries.
- `review`: the route may be useful, but caveats or invalid candidates prevent clean adoption.
- `reroute`: the route produces too little inspectable residual value for its boundary or cost.
- `block`: at least one cohort contains blocking residual risk.
- `no_data`: no scoreable residual traces were found.

Same-model QUINTE or MAGI can be useful when it exposes instability under
controlled perturbation. Calibration must still keep it separate from
heterogeneous or direct-evidence routes, because same-model agreement is not
independent confirmation.

## 5. Outcome Feedback

Route calibration becomes empirical only when later observations are recorded.
HIGHBALL uses `specs/residual-outcome-ledger.md` for that feedback layer.

Outcome ledgers bind follow-up command, test, runtime, source, human-review, or
external observations to traces, Action Packets, and calibration reports. They
can support, weaken, or complicate a route policy, but they do not create a
truth oracle. They document what was observed after the route decision.

Route-baseline comparison is specified in
`specs/residual-route-baselines.md`. It asks whether a useful-looking route
actually outperformed a cheaper or stronger same-boundary baseline.

Route policy synthesis is specified in `specs/residual-route-policy.md`. It
turns calibration plus outcome feedback into a reviewed policy recommendation
without modifying the router or authorizing action.

Route experiments are specified in `specs/residual-route-experiments.md`. They
register the target route group, baseline, outcome requirements, success
criteria, and stopping rules before a cohort is promoted into policy evidence.

Route execution reports are specified in `specs/residual-route-execution.md`.
They summarize execution completeness across Action Packets. Calibration says
whether traces were useful; execution reporting says whether the route
reliably produced the evidence its boundary contract required.

## 6. Non-Goals

Route calibration does not:

- choose the next route for a specific proposed action
- dispatch agents
- close residuals
- authorize protected writes
- estimate truth probability
- reward consensus without evidence
- treat malformed artifacts as absence of risk
- replace route-baseline comparison when multiple same-boundary routes exist
- replace outcome ledgers when follow-up evidence exists
- replace route experiment manifests or reviews when policy evidence should be
  pre-registered
- replace route execution reports when dispatch reliability is part of route
  evidence

Use `bin/route-residual-action.py` for a specific route decision, Action
Packets for boundary binding, and KENGEN/BANNIN for runtime authorization and
enforcement.
