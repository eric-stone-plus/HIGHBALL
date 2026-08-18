# QUINTE Runtime Boundary for HIGHBALL

HIGHBALL consumes QUINTE as one opaque, completed product. It does not become a
QUINTE scheduler merely because it runs on the same host or participates in an
outer campaign.

## Product-level contract

QUINTE owns its policy, one-family binding, provider credentials, adapters,
seven execution bindings, snapshots, phases, retries, pacing, worker cleanup,
receipts, and deterministic merge. HIGHBALL owns Product Router,
Authorization Gate, and Protected-Write Guard. The boundary is:

```text
request + residual trace
          │
          ▼
HIGHBALL chooses QUINTE
          │  host receipt / completed product only
          ▼
QUINTE owns all internal execution and lifecycle
```

The QUINTE provider binding is a runtime detail, not a HIGHBALL seat,
entitlement, quota, or a claim that the product is permanently tied to one
model family. HIGHBALL must validate the binding recorded in the QUINTE
policy/manifest and must not derive it from prose, command names, or an
environment variable copied into an action packet.

## Preferred receipt path

For new integrations, pass a durable successful `quinte host inspect` or
`reconcile` receipt to `bin/build-action-packet.py --quinte-receipt`. HIGHBALL
re-reads and validates the receipt locally, binds its state root, run identity,
manifest/result digests, and runtime digest, and performs no QUINTE subprocess.
`start`, `preflight`, and ordinary `status` receipts are observations and are
not product authorization.

The legacy `--quinte-result` path remains a local verifier path. If its optional
cross-check is used, `QUINTE_HOME` and `HIGHBALL_QUINTE_BIN` must be absolute and
stable; the binary's SHA-256 must match the manifest. A changed binary is an
integrity boundary: inspect or reconcile the old run and create a new run after
it is terminal. HIGHBALL must never resume, retry, poll, repair, or relaunch a
QUINTE run.

## Runtime binding migration

An outer campaign may explicitly migrate its current executable binding while
preserving historical QUINTE products. The migration is valid only when its
append-only receipt chain authorizes the historical runtime digest and the
historical manifest, inspect proof, result bytes, and result digest agree.
HIGHBALL should accept such a completed product as evidence of the run that
actually produced it; it must not rewrite the product to the new digest.

For a new product, HIGHBALL expects the current binding and exact digest in the
fresh host receipt. It must reject an unchained digest, a mutable/replaced
executable path, a receipt whose path or state root does not bind to the run,
and any ledger or migration record that was edited without a matching receipt.
Migration itself belongs to the outer campaign coordinator, not Product Router
or Protected-Write Guard. If migration evidence is incomplete, route to review
or block; do not infer continuity.

## Parser and transport failures

Provider transport parsing is QUINTE-owned. A stream that contains a valid earlier
LaneOutput followed by a malformed or schema-invalid final candidate is a
failed QUINTE execution, not a partially acceptable HIGHBALL product.
HIGHBALL must not concatenate text events, choose an older draft, edit
`result.json`, or classify a provider's model prose as a typed retry signal.
The only accepted product is the verified, current result bound by the QUINTE
manifest and host receipt.

When investigating a rejection, preserve the QUINTE raw event/stdout/stderr
bytes and receipt paths for the product owner. Do not copy provider credentials
or sensitive evidence into HIGHBALL packets or public reports.

## Boundary checklist

Before a QUINTE result can contribute to an Action Packet, verify all of the
following locally:

- the receipt operation is `inspect` or an eligible terminal `reconcile`;
- state root, run ID, receipt path, manifest identity, and result path agree;
- manifest/result/brief/snapshot digests and runtime digest match;
- the result is verified, actionable, completed, and current;
- all seven bindings share one declared model family in the product evidence;
- action scope and affected paths match the packet; authorization is handled by
  HIGHBALL's independent gate.

Any mismatch is fail-closed. A valid QUINTE result is evidence for a proposed
action, never authorization by itself.

The authoritative QUINTE host and migration details live in
[`QUINTE/specs/HOST.md`](https://github.com/eric-stone-plus/QUINTE/blob/main/specs/HOST.md)
and
[`QUINTE/specs/RUNTIME-MIGRATION.md`](https://github.com/eric-stone-plus/QUINTE/blob/main/specs/RUNTIME-MIGRATION.md).
