# SHIMEI Routing

> 指名: select the bounded product route, then bind it to one real entrypoint.

SHIMEI is HIGHBALL's outer routing identity constraint. Residual routing first
selects an instrument such as direct evidence, MAGI, QUINTE, human review, or
block. SHIMEI then verifies that the selected product route has one installed,
native entrypoint.

## QUINTE Binding

QUINTE is one atomic SHIMEI route. The active binding resolves the installed
`quinte` executable:

```bash
command -v quinte
```

```powershell
Get-Command quinte -ErrorAction SilentlyContinue
```

Package-manager shims are valid installed entrypoints when the platform command
resolver finds them. An absolute path is also valid after verification. Custom
dispatch wrappers are forbidden because they can reintroduce scheduler policy
outside the product boundary.

SHIMEI may pass the task and product-level options exposed by the `quinte` CLI.
It then waits for the product-level outcome. It must not call a QUINTE agent,
auditor, adapter, provider, model, or phase command directly.

## Ownership Boundary

The QUINTE scheduler exclusively owns:

- its roster, phases, prompt contracts, and internal verdict flow
- adapters, providers, models, credentials, and token-plan behavior
- lane dispatch, ordering, concurrency, and isolation
- artifacts, heartbeats, worker identity, cleanup, and finalization
- retry classification, retry budgets, and backoff
- R2 serial pacing and typed, bounded retry for HTTP 429 responses

HIGHBALL does not inspect or override those decisions. In particular, it must
not fan out R2, add a host-level retry loop, replay one internal lane, or route
around a failed internal attempt. That would create two schedulers with
conflicting safety and rate-limit behavior.

## Product Outcome

SHIMEI consumes only the `quinte` command's product-level status and result. A
missing or unsuccessful result can block the outer action. HIGHBALL does not
repair result files, interpret per-lane outputs, or infer success from internal
partial progress.

BANNIN may require a completed QUINTE trail for a protected write and validate
the residual closure presented at that boundary. KENGEN separately determines
whether the resulting external action is authorized. Neither component becomes
a QUINTE scheduler.

## Other Routes

Other instruments may have their own atomic product binding. They do not grant
SHIMEI permission to reach inside QUINTE or substitute an internal QUINTE
route. A failed QUINTE product invocation remains a failed QUINTE product
invocation until QUINTE reports a product-level outcome.

MAGI is optional. A host may have zero MAGI entrypoint. When residual routing
selects MAGI without a verified entrypoint, SHIMEI must fail closed into
`human-review` or `block` rather than inventing commands or borrowing QUINTE
lanes.

Process cleanup for QUINTE workers remains inside the `quinte` product
boundary. SHIMEI, KENGEN, and BANNIN must not scan for or kill QUINTE-owned
child processes by agent name.

## Distribution

SHIMEI is authored in HIGHBALL and mirrored into the current
`hermes-technical-profile-mac` and `hermes-technical-profile-win`
repositories. Those profile repos are distribution packages, not independent
authorities. Archived `hermes-core-rules-*` repositories are not updated.

The v1 `schemas/shimei-host-overlay.schema.json` and
`bin/validate-shimei-host-overlay.py` describe the retired per-agent overlay.
They remain available for archived-overlay validation only and must not be used
as an active QUINTE dispatch contract.
