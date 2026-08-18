# HIGHBALL

HIGHBALL is the deterministic control plane around review and verification
products. It owns three technical boundaries and nothing inside an agent
runtime:

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

HIGHBALL treats the review runtime as an opaque product:

- **QUINTE** is the five-school adversarial review runtime defined by the
  QUINTE repo specs under the single-vendor doctrine. All five lane bindings
  and both finalization bindings must use one declared model family. HIGHBALL
  binds one completed Result `2.1` and Manifest `2.0`; it never invokes an
  internal command, adapter, provider, or model endpoint.

Profile digests and model-family bindings are separate provenance fields.
Neither field is a calibrated correctness or statistical-independence metric.

## Routing

`bin/route-residual-action.py` applies the active routing contract:

- executable or directly source-verifiable claims use `direct-evidence`;
- adversarial review, including high-risk, irreversible, and architecture-level
  final judgment, uses `QUINTE`;
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
cargo build --release   # ships `highball` and `build-action-packet`

highball build-action-packet request.json trace.json \
  --quinte-result /trusted/quinte/runs/RUN_ID/result.json

highball build-action-packet request.json trace.json \
  --quinte-receipt /trusted/quinte/host/receipts/INVOCATION_ID.json

# Same argv as the former Python script (no subcommand):
#   target/release/build-action-packet request.json trace.json --quinte-receipt RECEIPT

highball validate-action-packet packet.json
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
That direct path is a local verifier operation (it does not schedule QUINTE),
but its optional CLI cross-check is now fail-closed: callers must set
`QUINTE_HOME` and `HIGHBALL_QUINTE_BIN` to absolute, stable paths. A configured
binary is never silently replaced by PATH lookup, and its SHA-256 must match
`manifest.runtime_sha256`. After a binary replacement, inspect/reconcile the
old run and create a new run; do not resume it through a changed executable.

Production direct-binding example:

```bash
export QUINTE_HOME=/absolute/path/to/quinte-state
export HIGHBALL_QUINTE_BIN=/absolute/path/to/quinte
sha256sum "$HIGHBALL_QUINTE_BIN"
highball build-action-packet request.json trace.json \
  --quinte-result "$QUINTE_HOME/runs/RUN_ID/result.json"
```

For new automation, prefer `--quinte-receipt` so HIGHBALL remains an opaque,
no-subprocess consumer of a separately captured `quinte host inspect` receipt.

The packet is fail-closed: missing, stale, moved, replayed, cross-task,
incomplete cross-review, non-PASS final judgment, or digest-drifted products
cannot authorize an action.

## Ownership

- HIGHBALL owns routing, authorization, and outer protected-write checks.
- QUINTE owns its policy, lifecycle, retry, pacing, evidence, and verdict.
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

Apache-2.0
