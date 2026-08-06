# HIGHBALL

HIGHBALL is the deterministic control plane around Hermes products. It owns
three technical boundaries and nothing inside an agent runtime:

- **Product Router** selects one verified atomic product entrypoint.
- **Authorization Gate** requires explicit user authorization for protected
  external actions.
- **Protected-Write Guard** validates the current Action Packet before a
  protected engineering write proceeds. Protected product source, schemas,
  container/runtime configuration, protocol docs, and control scripts are all
  inside this boundary.

Some Trace `1.1` artifacts retain the `RASHOMON` namespace for schema
compatibility. HIGHBALL treats that name as format metadata only; it has no
routing, authorization, or execution semantics.

## Product Boundaries

HIGHBALL treats both review runtimes as opaque products:

- **QUINTE** is a single-family review runtime. All five lane bindings and both
  finalization bindings must use one declared model family. HIGHBALL binds one
  completed Result `2.1` and Manifest `2.0`; it never invokes an internal
  command, adapter, provider, or model endpoint.
- **MAGI** is the high-intensity triadic cross-verification runtime. Three
  isolated Hermes profiles each produce a thesis and a same-family QUINTE
  dossier. After freezing, six anonymous directed reviews and a final
  adjudicator produce an actionable `PASS`, `BLOCK`, or `ESCALATE`. HIGHBALL
  accepts only a structurally valid, completed `magi verify-product` summary,
  never a trace alone. Only a final `PASS` can authorize action; `BLOCK` and
  `ESCALATE` remain valid completed products but force the packet to block.

Profile digests and model-family bindings are separate provenance fields.
Neither field is a calibrated correctness or statistical-independence metric.

## Routing

`bin/route-residual-action.py` applies the active routing contract:

- executable or directly source-verifiable claims use `direct-evidence`;
- bounded adversarial review uses `QUINTE`;
- high-risk, irreversible, or architecture-level final judgment uses `MAGI`;
- credential, deletion, deployment, financial, and legal actions require
  `human-review` and explicit authorization where applicable;
- missing required evidence or open high-risk residuals use `block`.

The router chooses a product; it does not schedule that product. See
[`specs/product-routing.md`](specs/product-routing.md) and
[`specs/residual-routing.md`](specs/residual-routing.md).

## Action Packets

Action Packet `2.0` binds one route request, one residual trace, the selected
atomic product, and any required user authorization:

```bash
python3 bin/build-action-packet.py request.json trace.json \
  --quinte-result /trusted/quinte/runs/RUN_ID/result.json

python3 bin/build-action-packet.py request.json trace.json \
  --quinte-receipt /trusted/quinte/host/receipts/INVOCATION_ID.json

python3 bin/build-action-packet.py request.json trace.json \
  --magi-trial /trusted/magi/trials/TRIAL_ID

python3 bin/validate-action-packet.py packet.json
bash lib/protected-write-guard.sh --check session.log --action-packet packet.json
```

Use `--authorization authorization.json` when the route requires an explicit
user decision. `bin/consume-authorization.py` atomically consumes that
short-lived authorization immediately before the external action.
The guard validates an immutable packet snapshot and consumes only the exact
authorization digest bound into that snapshot.

`--quinte-receipt` accepts either a durable QUINTE host receipt or a saved
`quinte host inspect --json` envelope. HIGHBALL re-reads the durable receipt,
binds it to the configured QUINTE state root and canonical `result.json`, and
performs product validation locally. It accepts only verified `inspect` or
`reconcile` observations; it never invokes `quinte`, starts a run, resumes a
worker, polls status, or schedules recovery. `--quinte-result` remains
available for callers that deliberately use the legacy direct result binding.

The packet is fail-closed: missing, stale, moved, replayed, cross-task,
same-family-disguised MAGI, incomplete cross-review, non-PASS final judgment,
or digest-drifted products cannot authorize an action.

## Ownership

- HIGHBALL owns routing, authorization, and outer protected-write checks.
- QUINTE owns its policy, lifecycle, retry, pacing, evidence, and verdict.
- MAGI owns container/profile isolation, dossier freezing, anonymous exchange,
  final adjudication, and deterministic product verification.
- Platform technical-profile repositories distribute these common rules and
  platform-specific credential/container setup. They are not protocol
  authorities.

## Evidence Analysis

The remaining `bin/build-route-*`, `bin/validate-route-*`, residual scoring,
calibration, experiment, outcome-ledger, and evidence-chain tools are
non-authorizing analytics. They may recommend keep/watch/reroute/block but may
not modify product routing or grant permission.

## Specs

- [Product routing](specs/product-routing.md)
- [Residual routing](specs/residual-routing.md)
- [Action packet](specs/action-packet.md)
- [Residual closure](specs/residual-closure.md)
- [Residual route analytics](specs/residual-route-policy.md)

## Verification

```bash
scripts/check-local.sh
```

## License

MIT
