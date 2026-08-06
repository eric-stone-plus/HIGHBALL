# Action Packet

Action Packet `2.0` is the closed, fail-closed evidence bundle for one proposed
action. It contains:

- the closed route request and deterministically derived route;
- one Trace `1.1`, its validation result, and quality metrics;
- exactly one required atomic product: QUINTE Result `2.1`/Manifest `2.0`, or a
  MAGI Product Summary `1.0` returned by `magi verify-product`;
- one optional short-lived, action-bound user authorization;
- the recomputed `pass`, `review`, or `block` boundary decision.

## Action Binding

`action_binding_sha256` is the canonical, sorted-key, whitespace-free UTF-8
JSON digest of `question`, `action_boundary`, `change_class`, and ordered
`affected_paths`. `action_scope` is compared exactly with the selected product.
Strict (`protected_write` or `irreversible`) boundaries require at least one
unique, non-empty affected path.

Cross-task, moved, tampered, stale, or scope-drifted products block.

## QUINTE Binding

`--quinte-result` binds one canonical `result.json`. HIGHBALL validates the
active QUINTE contract, completed status, manifest/result/brief digests, run
identity, installed runtime digest, `quinte inspect`, five R1/R2 lane artifact
pairs, and all seven same-family route bindings. HIGHBALL does not schedule a
lane.

`--quinte-receipt` is the host-integrated binding. It accepts one durable
`host/receipts/<invocation-id>.json` file or a saved successful
`quinte host inspect --json` envelope. The embedded `receipt_path`, invocation
identity, state root, run identity, manifest/result digest, and verified result
binding must all agree with the canonical QUINTE run bundle. Only `inspect` and
`reconcile` receipts with `result.verified=true` are eligible; `start`,
`preflight`, and `status` receipts are observation-only and are rejected for
product authorization. HIGHBALL validates the bound product locally with no
QUINTE subprocess, retry, resume, polling loop, or scheduling side effect.
Receipt provenance is retained in `product_evidence.product` as
`host_receipt_ref`, `host_receipt_sha256`, and `host_receipt_operation`.

## MAGI Binding

`--magi-trial` invokes `magi verify-product` and binds its closed product
summary. HIGHBALL verifies the summary digest, action binding, completed
`PASS`/`BLOCK`/`ESCALATE` decision, three distinct families, three distinct
profile digests, three distinct QUINTE runs, and six directed cross-reviews.
MAGI independently performs the deep artifact validation. `BLOCK` and
`ESCALATE` are structurally valid completed products, but are non-authorizing
and force the Action Packet to block. A MAGI trace alone never satisfies this
binding.

## Authorization

Protected external actions may require `--authorization`. The artifact records
one user decision, exact action binding and scope, unique ID, and an issue/expiry
window no longer than eight hours. `bin/consume-authorization.py` atomically
consumes it immediately before the action; replay blocks. The Protected-Write
Guard validates an immutable Action Packet snapshot and requires the consumed
authorization bytes to match the `artifact_sha256` recorded in that snapshot.
Replacing either file after packet creation therefore fails closed.

## Decision

Malformed traces, route/trace mismatch, required product absence, product
verification failure, `BLOCK`/`ESCALATE`, missing authorization, or quality
gate `block` all block. Quality gate `review` remains non-authorizing. Only a
fully valid packet with decision `pass` exits zero.

Exit codes:

- `0`: valid and authorizing `pass`;
- `1`: valid but non-authorizing `review` or `block`;
- `2`: malformed or internally inconsistent.

The schema is `schemas/action-packet.schema.json`; shared identifiers and
canonical digest rules live in `bin/highball-contracts.py`.
