# Residual Route Policy

> Route policy reports synthesize calibration and outcome evidence. They do not
> authorize action and do not modify the live router.

## 1. Purpose

Route calibration reports say how a route performed as a residual-evidence
producer. Outcome ledgers say what later evidence showed. A route policy report
combines those two artifacts into a conservative recommendation for similar
future boundaries.

When multiple same-boundary routes exist, route-baseline reports should be read
before policy synthesis. A route may be informative in isolation but still lose
to a cheaper, stronger, or more direct baseline.

When a route policy will justify a future default or protocol change, a route
experiment review should be read before policy synthesis. It verifies that the
route cohort was evaluated against a pre-run manifest rather than post hoc
sample selection.

This closes the loop without letting the system rewrite itself automatically.
Policy reports are evidence for maintainers and future protocol changes, not
runtime authority.
Route change proposals are the next artifact when maintainers want a concrete
review candidate; see `specs/residual-route-change-proposals.md`.

## 2. Inputs

`bin/build-route-policy-report.py` consumes a validated route calibration
report, validated follow-up outcome ledger, optional same-boundary route
baseline report, optional route experiment review, and optional route execution
report.

Route-baseline reports from `specs/residual-route-baselines.md` can only make
policy synthesis more conservative. A baseline report may block or reroute a
target route, but it does not by itself upgrade a target route to `keep`.

Route experiment reviews from `specs/residual-route-experiments.md` also make
policy synthesis more conservative. A `supports_policy_review` verdict leaves
the normal policy rule intact. `needs_more_evidence` prevents `keep`.
`stop_blocked` yields `block`. `plan_violation` yields `insufficient` unless
the underlying calibration, baseline, or outcome evidence is already blocking.

Route execution reports from `specs/residual-route-execution.md` summarize
whether Action Packets for this route actually had complete required execution
evidence. They are conservative route-reliability gates: blocked dispatch
evidence blocks policy reuse, degraded execution reroutes future work, and
missing execution evidence prevents clean adoption.

The builder rejects invalid inputs. The validator is
`bin/validate-route-policy-report.py`; the schema is
`schemas/route-policy-report.schema.json`.

Use `bin/validate-evidence-chain.py` when the report will be used as evidence
for a protocol or routing change. It follows the report references into the
calibration report, outcome ledger, Action Packet, and residual traces, then
checks route group consistency, residual id existence, and source-file
presence.

## 3. Recommendations

- `keep`: calibration and outcome evidence support keeping the route policy for similar boundaries.
- `watch`: evidence is useful but mixed, weak, or still under review. Keep collecting outcomes.
- `reroute`: later evidence or calibration weakness suggests a stronger, cheaper, or more direct route.
- `block`: calibration shows blocking risk for the route group. Do not reuse for similar protected boundaries until resolved.
- `insufficient`: inputs do not support a policy move.

## 4. Derivation Rule

The report derives the recommendation conservatively:

1. Baseline `block_target` yields `block`.
2. Calibration `block` yields `block`.
3. Baseline `prefer_baseline` yields `reroute`.
4. Outcome `weakens_route` yields `reroute`.
5. Calibration `reroute` or `no_data` yields `reroute`, unless outcome evidence
   is supportive enough to downgrade that to `watch`.
6. Outcome `mixed` or `insufficient` yields `watch` for otherwise usable routes.
7. Calibration `adopt` plus outcome `supports_route` yields `keep`.
8. Calibration `review` yields `watch`.
9. Anything else yields `insufficient`.
10. If an experiment review is supplied, apply its gate after the preceding
    rule: accepted leaves the recommendation intact, watch prevents `keep`,
    block yields `block`, and insufficient prevents a positive policy move.
11. If a route execution report is supplied, apply its gate last: accepted
    leaves the recommendation intact, watch prevents `keep`, reroute yields
    `reroute` unless the route is already blocked, and block yields `block`.

`bin/validate-route-policy-report.py` recomputes this rule and rejects tampered
reports.

`bin/validate-evidence-chain.py` adds cross-artifact checks that the route
policy report alone cannot prove:

- Calibration report and outcome ledger references must exist so policy evidence remains inspectable.
- Optional baseline report references must exist when baseline evidence is used.
- Policy route group must match calibration and outcome route groups so a recommendation cannot mix unrelated cohorts.
- Policy baseline summary must match the referenced baseline report for the target route so baseline evidence cannot be softened or ignored.
- Optional experiment review must match the referenced manifest and reports so a route that failed its pre-run plan cannot be promoted.
- Experiment review pairing references must validate when a route pairing report is supplied.
- Policy experiment summary must match the referenced experiment review so stopping rules cannot be softened.
- Optional route execution report must be recomputable from referenced Action Packets so dispatch reliability cannot be softened or ignored.
- Policy execution summary must match the referenced execution report so route-level execution gates cannot be edited after generation.
- Outcome residual ids must exist in referenced traces and Action Packets.
- Outcome trace refs should be represented in calibration group sources when sources are declared.
- Outcome calibration refs must match the policy calibration report.

## 5. Non-Authorization

Route policy reports do not:

- modify `bin/route-residual-action.py`
- change SHIMEI bindings
- authorize protected writes, push, deployment, legal, financial, or deletion
  actions
- prove truth
- replace Action Packets
- replace outcome ledgers
- replace route experiment manifests or reviews
- apply route change proposals
- replace evidence-chain validation when cross-artifact references matter

They provide a reviewable evidence packet for a future human or protocol change
to consider.
