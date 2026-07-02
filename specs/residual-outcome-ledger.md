# Residual Outcome Ledger

> Outcome ledgers record follow-up evidence after a trace, Action Packet, or
> route calibration report. They are empirical feedback artifacts, not truth
> oracles.

## 1. Purpose

Residual traces and calibration reports are forward-looking artifacts. They say
what was found, what was closed, what remained risky, and whether a route looked
worth using again.

An outcome ledger records what happened later. It connects route evidence to
observable follow-up evidence so route calibration can move from proxy metrics
to empirical feedback.

## 2. Inputs

An outcome ledger may reference:

- `trace_ref`: residual trace whose residual ids are being followed up.
- `action_packet_ref`: Action Packet that bound the trace to a proposed action.
- `calibration_report_ref`: route calibration report influenced by the outcome.

Each entry must reference at least one of these artifacts.

## 3. Outcome Classes

- `verified_positive`: follow-up evidence supports the trace closure, route decision, or expected behavior.
- `verified_negative`: follow-up evidence contradicts the trace closure, route decision, or expected behavior.
- `inconclusive`: follow-up evidence was gathered but does not resolve the question.
- `regression`: later behavior regressed after a previously supported outcome.

These are observation classes, not truth probabilities.

## 4. Evidence Types

- `command`: CLI result, compilation, or script output.
- `test`: automated test result or fixture.
- `runtime`: runtime behavior, logs, monitoring, or browser check.
- `source`: file, source citation, or external document.
- `human_review`: scoped human review or waiver result.
- `external_observation`: production feedback, user report, or later incident.

Every entry needs non-empty evidence. A ledger without evidence is just a
claim about a claim.

## 5. Summary

The ledger summary must match the entries:

- `entry_count`: number of outcome entries.
- `verified_positive_count`: count of supportive follow-up observations.
- `verified_negative_count`: count of contradicting follow-up observations.
- `inconclusive_count`: count of unresolved follow-up observations.
- `regression_count`: count of regressions after prior support.
- `calibration_signal`: `supports_route`, `weakens_route`, `mixed`, or `insufficient`.

`bin/validate-outcome-ledger.py` recomputes the summary. Tampered counts or
softened calibration signals fail validation.

## 6. Calibration Semantics

Outcome ledgers affect route policy as evidence, not authority:

- `supports_route`: follow-up observations support using this route for similar boundaries.
- `weakens_route`: follow-up observations contradict or regress enough to require rerouting or review.
- `mixed`: the route surfaced useful evidence but did not cleanly predict later outcomes.
- `insufficient`: evidence exists but is too weak or unresolved to move route policy.

When outcome ledgers conflict with route calibration reports, prefer the later
observed evidence but preserve both artifacts. Do not rewrite historical
calibration reports to make the record look cleaner.

## 7. Non-Goals

Outcome ledgers do not:

- authorize action
- prove philosophical truth
- replace residual traces
- replace Action Packets
- replace route calibration reports
- rewrite earlier outputs
- treat one follow-up observation as universal route performance

They close the empirical loop: trace, packet, calibration report, observed
outcome.

Use `specs/residual-route-policy.md` when a calibration report and outcome
ledger need to be synthesized into a route-policy recommendation. The policy
report remains evidence for humans and future routing changes; it does not
change live HIGHBALL routing by itself.

When outcome entries reference traces or Action Packets, validate the whole
chain with `bin/validate-evidence-chain.py`. A ledger can be locally valid while
still pointing at the wrong trace or a residual id that does not exist.
