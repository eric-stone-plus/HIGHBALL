# Product Routing

The Product Router maps an evidence requirement to one installed, atomic
product entrypoint. It never reaches inside that product.

## Entrypoints

Resolve native commands before dispatch:

```bash
command -v quinte
command -v magi
```

```powershell
Get-Command quinte -ErrorAction SilentlyContinue
Get-Command magi -ErrorAction SilentlyContinue
```

Package-manager shims are acceptable after resolution. Undocumented wrappers
are not acceptable for protected dispatch because they hide policy drift.

## QUINTE

QUINTE is one single-family adversarial review product. The scheduler alone
owns parties, arbiters, adapters, models, credentials, phases, concurrency,
retry, pacing, artifacts, cleanup, and finalization. HIGHBALL supplies only
product-level inputs and consumes the completed product-level outcome.

HIGHBALL must not fan out R2, retry a lane, substitute a provider, invoke an
arbiter, repair an artifact, or infer success from partial progress.

## MAGI

MAGI is one triadic cross-verification product. It owns three isolated Hermes
profiles, three same-family QUINTE products, freeze-before-exchange, six
anonymous directed cross-reviews, final adjudication, and deterministic
verification. HIGHBALL consumes only `magi verify-product TRIAL_DIR`.

A verified final `BLOCK` or `ESCALATE` is a completed MAGI product, not a
runtime failure. The Product Router preserves that result, while the Action
Packet independently permits action only when the final decision is `PASS`.

A residual trace without a verified atomic MAGI product is insufficient. A
missing MAGI entrypoint fails closed into human review or block; HIGHBALL must
not simulate MAGI with QUINTE parties.

## Outer Enforcement

The Authorization Gate independently decides whether an external action is
allowed. The Protected-Write Guard independently checks the current Action
Packet. Neither becomes a QUINTE or MAGI scheduler.

Process cleanup remains within each product boundary. Host rules must not scan
for or kill internal workers by agent name.

## Distribution

This contract is authored in HIGHBALL and mirrored into current macOS, Linux,
and Windows technical-profile repositories plus the active host profile.
Platform profiles contain path, credential, and container details only; they
must not fork this common routing policy.
