# Residual Route Execution

> Route execution reports summarize whether a route actually ran when Action
> Packets depended on execution evidence. They do not dispatch agents,
> authorize action, or modify routing policy.

Active reports consume only Action Packet `1.1` atomic product outcomes. Legacy
phase ledgers are archive evidence and are not accepted as active execution.

## 1. Purpose

Action Packets decide one proposed action. A route execution report asks a
different question: across a packet cohort, did the selected route reliably
produce the execution evidence it claimed to require?

This matters most for QUINTE. A QUINTE trace may be structurally valid while
the atomic CLI invocation did not produce a completed product outcome. The
Action Packet blocks that single action. The route execution report preserves
the wider product-level signal so a future route policy cannot ignore repeated
invocation instability.

## 2. Inputs

`bin/build-route-execution-report.py` consumes validated Action Packets. It
does not read QUINTE phase, lane, agent, retry, or pacing records. This keeps
the scope tied to atomic product outcomes at concrete boundaries.

Each packet contributes:

- route group derived from trace instrument, base-model relation, and action boundary
- selected route and trace instrument
- action decision
- whether execution evidence was required
- execution status: `not_required`, `missing`, `complete`, `blocked`,
  `degraded`, or `invalid`
- bound QUINTE run ID, result digest, and action-binding digest when present
- execution errors copied from the packet

The builder rejects mixed route groups unless a target route group is supplied.
The validator is `bin/validate-route-execution-report.py`; the schema is
`schemas/route-execution-report.schema.json`.

## 3. Execution Gates

The report derives an execution gate:

- `accepted`: every required packet has complete execution evidence.
- `watch`: at least eighty percent of required packets are complete, but one or more are missing.
- `reroute`: required completion is below eighty percent, or any packet has degraded execution evidence.
- `block`: any packet is invalid or contains blocked execution evidence.
- `insufficient`: no packets, or no packets requiring execution evidence, were available.

These gates are route-level reliability signals. They are not truth estimates.
They say whether the route can be operationally trusted to produce the evidence
its own boundary contract requires.

## 4. Policy Use

`bin/build-route-policy-report.py` may consume a route execution report as an
optional conservative gate after calibration, outcome, baseline, and experiment
review evidence.

Execution evidence can only make the recommendation more conservative:

- `accepted`, `not_provided`, and `insufficient` leave the current policy rule intact.
- `watch` prevents a positive `keep` recommendation.
- `reroute` yields `reroute` unless stronger evidence already blocks the route.
- `block` yields `block`.

This prevents a route from being promoted because its traces look useful while
its dispatch layer is unreliable.

## 5. Evidence Chain

`bin/validate-evidence-chain.py` validates route execution reports as root
artifacts and as route policy inputs. It recomputes each execution report from
its referenced Action Packets, then checks that any policy summary matches the
execution report exactly.

The chain is intentionally layered:

- QUINTE owns and validates all internal execution state.
- HIGHBALL Action Packets decide one action from route, trace, quality, and the atomic product outcome.
- HIGHBALL route execution reports summarize Action Packet execution reliability.
- HIGHBALL route policy reports may use that summary as a conservative route gate.

## 6. Non-Authorization

Route execution reports do not:

- dispatch agents
- authorize protected writes or irreversible operations
- replace or interpret QUINTE internal execution records
- replace Action Packets
- prove truth
- mutate route policy

They make operational route reliability visible enough to affect reviewed
future policy decisions.
