# Residual Route Change Proposals

> Route change proposals convert route policy evidence into reviewable change
> candidates. They do not edit files, update SHIMEI, or authorize action.

## 1. Purpose

Route policy reports recommend what should happen to future route policy. A
proposal records what a maintainer might change, which files or overlays would
be affected, and which gates must pass before any change is made.

This is the boundary between evidence and modification. HIGHBALL may build a
proposal, but it must not apply it automatically.

## 2. Inputs

`bin/build-route-change-proposal.py` consumes a validated route policy report.
The schema is `schemas/route-change-proposal.schema.json`. The validator is
`bin/validate-route-change-proposal.py`.

Use `bin/validate-evidence-chain.py` before using a proposal as review
evidence. It verifies the proposal against the referenced policy report and
then verifies the policy report against calibration, baseline, outcome, Action
Packet, trace artifacts, and route experiment review artifacts when present.

## 3. Proposed Changes

- `keep_route_group`: record evidence supporting continued use under normal gates.
- `watch_route_group`: collect more outcomes before changing route policy.
- `reroute_route_group`: prefer an alternative route for similar future work.
- `block_route_group`: block default use for similar future work until risk is resolved.
- `collect_evidence`: gather more calibration or outcome evidence.

`block_route_group` and `reroute_route_group` are intentionally conservative
and return non-zero validator status. They are valid proposals, not execution
permission.

## 4. Required Gates

Before a proposal affects routing documentation or a host overlay:

1. Validate the proposal evidence chain.
2. Complete maintainer review.
3. Update route documentation or host overlay only after review.
4. Run HIGHBALL route and evidence-chain tests.
5. Obtain KENGEN authorization before protected writes or push.

## 5. Non-Authorization

Route change proposals do not:

- modify `bin/route-residual-action.py`
- edit SHIMEI overlays
- change live host routing
- authorize protected writes, push, deletion, deployment, legal, or financial
  actions
- prove truth
- replace route policy reports

They are audit artifacts for future maintainer decisions.
