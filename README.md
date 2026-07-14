# HIGHBALL (ハイボール)

> Hermes outer control plane for routing and guarding bounded operations.

HIGHBALL is the outer control plane around the Hermes host. It answers only
boundary questions:

- Which bounded product route should handle this work?
- Which evidence route should this residual-bearing action take?
- Is the resulting external action authorized?
- May a protected write proceed with the available residual closure?

When SHIMEI selects QUINTE, it invokes the installed `quinte` CLI as one atomic
product boundary. HIGHBALL does not reconstruct, inspect, or override the
QUINTE workflow behind that boundary.

`hermes-technical-profile-mac` and `hermes-technical-profile-win` are the
current platform profile repositories. They mirror operational rules into
concrete Hermes profiles. Archived `hermes-core-rules-*` repositories are
historical records and must not receive new runtime rules. None of these is a
separate protocol authority.

## Runtime Components

Only these components can route, authorize, or guard a Hermes operation.

- SHIMEI, 指名: selects a bounded product route and binds it to one verified
  entrypoint. For QUINTE, that entrypoint is the atomic `quinte` CLI.
- KENGEN, 権限: decides whether an external action may happen. It owns the
  authorization perimeter for push, delete, deployment, and config writes.
- BANNIN, 番人: guards protected writes and enforces residual closure before
  the action crosses its boundary.

Non-runtime material belongs outside the dispatch path:

- RASHOMON owns non-runtime philosophy and cultural context.
- STORM / Co-STORM may inform SOUL prompt construction.
- Neither creates a HIGHBALL runtime component, agent, vote, or permission.

## SHIMEI — Product Route Identity

SHIMEI is the routing contract for Hermes. It binds a selected product route to
a verified entrypoint. Each host resolves executable entrypoints
with `command -v` or `Get-Command` before dispatch. Package-manager shims are
acceptable installed entrypoints after verification. Custom wrapper dispatch
scripts are forbidden for protected dispatch because they hide drift and stale
assumptions.

For QUINTE, SHIMEI binds exactly one product route to the installed `quinte`
entrypoint. It may pass the task and product-level options supported by that
CLI, then waits for the CLI's product-level outcome. It does not bind or invoke
QUINTE agents, auditors, adapters, providers, or model-specific commands.

QUINTE alone owns its roster, phases, lane dispatch, concurrency, provider and
model selection, credentials, artifacts, worker lifecycle, cleanup, retry, and
finalization. In particular, the QUINTE scheduler owns R2 serial pacing and
typed, bounded retry for HTTP 429 responses. HIGHBALL must not add a second
retry loop, fan out R2, or substitute another route after a QUINTE attempt.

MAGI remains a Hermes Agent Protocol. A host may bind MAGI perspectives only
through an explicit SHIMEI overlay. Do not dispatch historical or inferred
routes.

SHIMEI treats the `quinte` process status and product-level result as the route
outcome. QUINTE decides whether its internal attempts and outputs are valid.
HIGHBALL may block the outer action when the product outcome is absent or
unsuccessful, but it must not repair internal artifacts or retry internal
lanes.

The existing v1 SHIMEI host-overlay schema and validator describe the retired
per-agent routing contract. They remain compatibility tools for archived
overlays and are not an active QUINTE dispatch surface.

## Rules Repositories

- `hermes-technical-profile-mac`: current macOS profile distribution.
- `hermes-technical-profile-win`: current Windows profile distribution.
- `.hermes/profiles/technical`: host-local Hermes technical profile consumed
  by the current runtime.

Protocol content belongs in the owning repo: QUINTE protocol in QUINTE, MAGI
protocol in MAGI, RASHOMON philosophy in RASHOMON, and Hermes host operation
rules in HIGHBALL. The technical-profile repos mirror these decisions into the
runtime. If the routing contract changes, update HIGHBALL first. If only a
concrete host binding changes, update the active technical profile and its
current macOS/Windows repositories.

## KENGEN — Authorization Perimeter

KENGEN defines which Hermes operations require explicit user authorization.

- `git push` is blocked by default. The user must explicitly say `push`, `推`, or `推送` in the current session.
- Destructive delete or reset is blocked by default and requires tool approval or explicit user instruction.
- Credential or config mutation is blocked by default and requires explicit task scope plus pre-write verification.

KENGEN is policy. It says whether an action is allowed.

## BANNIN — Runtime Guard

BANNIN enforces protected-write checks in the Hermes runtime. It is deliberately
smaller than the old governance model:

- detect protected engineering writes to public repo `README*`, `specs/**`, and
  runtime scripts
- require a QUINTE trail before protocol or protected public-repo rewrites
- require high-risk findings in that trail to be closed, blocked, waived, or
  not applicable before protected writes proceed
- block unauthorized external actions through KENGEN policy

BANNIN is mechanism. It checks the current session and either passes or blocks.
The standalone shell guard enforces verdict-trail existence. When the verdict
contains a JSON residual closure ledger, it also blocks unresolved or
unsupported `HIGH`, `CRITICAL`, and `P0` findings before protected writes.
Historical verdicts without a ledger remain on the transitional warning path.
The reusable validator is `bin/validate-residual-trace.py`; it validates
RASHOMON-compatible traces embedded in markdown verdicts or stored as raw JSON
artifacts. It is used by `lib/bannin.sh`; downstream consumers should validate
their own fixture corpus outside the repository.

HIGHBALL also provides `bin/measure-residual-trace.py` for advisory quality
metrics: residual count, evidence coverage, action-blocking closure coverage,
open high-risk count, unsupported high-risk closure count, silent-collapse
signals, and trial-manifest signals such as independent first-pass count,
perturbation-axis count, same-model flag, contamination-risk count, and cost
presence. The measurement tool does not prove truth or authorize action; it
surfaces whether a trace is informative enough to rely on.

`bin/scan-residual-archive.py` scans debate archives or repository trees for
residual trace adoption. It is read-only: historical debates remain evidence,
while new verdicts can be measured for migration toward the trace contract.

`bin/score-residual-trial.py` scores residual trial evidence by combining
residual yield, closure strength, manifest strength, risk penalty, and
cost-normalized residual yield. The score is not truth probability and does not
authorize action; it helps compare whether a route is worth using again.

`bin/calibrate-residual-routes.py` scans trace cohorts and groups scored trials
by instrument, model relation, and action boundary. It reports route-level
adoption, review, reroute, or block recommendations, plus invalid trace
candidates that would otherwise disappear from the evidence ledger.
`schemas/route-calibration-report.schema.json` defines the portable report
shape, and `bin/validate-route-calibration-report.py` checks report structure,
count consistency, group totals, and derived recommendation.

`bin/build-route-baseline-report.py` compares a target route group against a
same-boundary baseline route group. It asks whether QUINTE, MAGI, direct
evidence, or human review earned its cost against a cheaper or stronger route.
`schemas/route-baseline-report.schema.json` defines the report shape, and
`bin/validate-route-baseline-report.py` recomputes deltas, verdicts, reasons,
and summary counts.

`bin/build-route-pairing-report.py` compares same-question target and baseline
traces for the same action boundary. It uses residual trace scoring rather than
LLM judge voting, then emits a non-authorizing route pairing report. The schema
is `schemas/route-pairing-report.schema.json`; the pair manifest schema is
`schemas/route-pair-manifest.schema.json`. Validators recompute reports from
the manifest and traces.

`bin/validate-outcome-ledger.py` validates residual outcome ledgers: follow-up
observations that connect traces, Action Packets, and calibration reports to
later command, runtime, source, human-review, or external evidence. Outcome
ledgers are empirical feedback artifacts; they do not turn HIGHBALL into a
truth oracle.

`bin/build-route-policy-report.py` combines a route calibration report, an
outcome ledger, and optionally a route baseline report, route experiment
review, or route execution report into a non-authorizing route policy report.
It recommends keep, watch, reroute, block, or insufficient evidence for similar
future boundaries. Baseline, experiment, and execution evidence can block or
reroute the target route, but they cannot by themselves upgrade the target to
keep.
`bin/validate-route-policy-report.py` recomputes that recommendation so the
report cannot be softened after generation.

`bin/build-route-execution-report.py` summarizes execution evidence across
Action Packets for a route group. It tracks complete, missing, blocked,
degraded, and invalid dispatch evidence and emits a conservative execution
gate for policy review. `bin/validate-route-execution-report.py` recomputes
that report from the referenced Action Packets.

`bin/validate-route-experiment-manifest.py` validates a pre-run route
experiment manifest: target route group, planned trace inputs, required
same-boundary baselines, route pairing requirements, outcome requirements,
success criteria, and stopping rules. `bin/build-route-experiment-review.py`
compares the manifest against the actual calibration, baseline, pairing, and
outcome artifacts, and
`bin/validate-route-experiment-review.py` recomputes the review. Experiment
reviews can be supplied to route policy reports as a conservative gate, but
they do not dispatch agents or authorize route changes.

`bin/build-route-change-proposal.py` turns a route policy report into a
non-authorizing proposal for maintainer review. It records candidate routing
policy changes, affected documentation or overlay paths, and required gates.
`bin/validate-route-change-proposal.py` recomputes the proposal from the policy
recommendation so a blocking or reroute proposal cannot be softened.

`bin/validate-evidence-chain.py` validates references from route policy reports
route baseline reports, route pairing reports, route experiment reviews, or
route change proposals into calibration reports, outcome ledgers, Action
Packets, route execution reports, residual traces, pair manifests, and
experiment manifests. It catches broken chains where each artifact is locally
valid but references the wrong route group, missing residual ids, wrong
baseline summaries, softened pairing reports, softened experiment reviews,
softened execution reports, softened proposals, or non-existent source files.

`bin/route-residual-action.py` chooses the next evidence route for a proposed
action: direct evidence, MAGI, QUINTE, human review, or block. It does not
dispatch agents or authorize the action; it makes the route decision explicit
before BANNIN and KENGEN enforcement.

`bin/build-action-packet.py` combines a route request, route decision, residual
trace, validation result, quality metrics, and required execution evidence into
one reviewable Action Packet for a proposed action. Active QUINTE integrations
bind an atomic product outcome with `--quinte-result` (`result.json`); the
builder and validator accept or block that product status only and do not
revalidate phase, lane, agent, retry, or pacing details. Per-phase dispatch
ledgers (`--dispatch-ledger`) remain available solely for archived packet
compatibility.
`schemas/action-packet.schema.json` defines the portable packet shape, and
`bin/validate-action-packet.py` independently recomputes route, validation,
quality, execution evidence, and boundary decision to catch malformed or
inconsistent packets.

`schemas/shimei-host-overlay.schema.json` documents the retired v1 per-agent
overlay shape for compatibility. Active integrations bind the `quinte`
entrypoint as one SHIMEI product route.

## Non-Runtime References

RASHOMON and STORM can explain why a prompt is framed a certain way. They do not
change SHIMEI routing, KENGEN authorization, or BANNIN checks.

## Retired From HIGHBALL

The following concepts are no longer HIGHBALL components:

- Per-agent QUINTE bindings and audit labels: QUINTE owns its complete internal
  workflow; HIGHBALL binds only the atomic `quinte` CLI.
- QUINTE process cleanup and output repair: the QUINTE scheduler owns worker
  lifecycle, recovery, and finalization.
- Other unimplemented governance labels: removed until there is a real
  maintained implementation.
- Theoretical foundation essays: move broad philosophy to RASHOMON.

## Specs

- [SHIMEI routing](specs/shimei-routing.md)
- [Retired process cleanup contract](specs/process-cleanup.md)
- [Action packet](specs/action-packet.md)
- [Residual closure](specs/residual-closure.md)
- [Residual routing](specs/residual-routing.md)
- [Residual trial scoring](specs/residual-trial-scoring.md)
- [Residual route calibration](specs/residual-route-calibration.md)
- [Residual route baselines](specs/residual-route-baselines.md)
- [Residual route pairing](specs/residual-route-pairing.md)
- [Residual route experiments](specs/residual-route-experiments.md)
- [Residual route execution](specs/residual-route-execution.md)
- [Residual outcome ledger](specs/residual-outcome-ledger.md)
- [Residual route policy](specs/residual-route-policy.md)
- [Residual route change proposals](specs/residual-route-change-proposals.md)

## License

MIT
