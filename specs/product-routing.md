# Product Routing

The Product Router maps an evidence requirement to one installed, atomic
product entrypoint. It never reaches inside that product.

## Entrypoints

Resolve native commands before dispatch:

```bash
command -v quinte
```

```powershell
Get-Command quinte -ErrorAction SilentlyContinue
```

Package-manager shims are acceptable after resolution. Undocumented wrappers
are not acceptable for protected dispatch because they hide policy drift.

## QUINTE

QUINTE is one single-family review product. Its scheduler alone owns internal
commands, adapters, models, credentials, phases, concurrency, retry, pacing,
artifacts, cleanup, and finalization. HIGHBALL supplies only product-level
inputs and consumes the completed product-level outcome.

HIGHBALL must not fan out a phase, retry a lane, substitute a provider, invoke
an internal finalizer, repair an artifact, or infer success from partial
progress.

## Outer Enforcement

The Authorization Gate independently decides whether an external action is
allowed. The Protected-Write Guard independently checks the current Action
Packet. Neither becomes a QUINTE scheduler.

The guard covers the product's implementation and contract surfaces (`src/`,
`schemas/`, `container/`, `configs/`, `skills/`, runtime manifests,
and protocol/control scripts), not only documentation.

Process cleanup remains within each product boundary. Host rules must not scan
for or kill internal workers by agent name.

## Distribution

This contract is authored in HIGHBALL and mirrored into current macOS, Linux,
and Windows technical-profile repositories plus the active host profile.
Platform profiles contain path, credential, and container details only; they
must not fork this common routing policy.
