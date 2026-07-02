# SHIMEI Routing

> 指名: bind the name to the real tool before dispatch.

SHIMEI is HIGHBALL's routing identity constraint. Hermes must dispatch
protected agent work through verified native CLI commands. Wrapper dispatch
scripts are stale by design because they hide tool drift and make route changes
harder to audit.

SHIMEI binds concrete routes after residual routing has selected the required
instrument. Residual routing decides whether the next evidence route is direct
evidence, MAGI, QUINTE, human review, or block. SHIMEI then verifies that the
selected route has a real host binding.

## Canonical Bindings

SHIMEI defines what must be bound, not the concrete public tool lineup.
Executable names, model/provider choices, credentials, and platform-specific
command lines live in the technical profile, host overlay, or platform rules
repository.

Each host resolves executable entrypoints before dispatch:

- POSIX overlays should record `command -v <route-cli>` evidence.
- PowerShell overlays should record `Get-Command <route-cli>` evidence.

Absolute paths are allowed after verification, but public examples must not
assume a single home directory such as `/Users/<name>` or `C:\Users\<name>`.
Package-manager shims such as `*.ps1`, `*.cmd`, npm shims, or bun shims count
as native installed entrypoints when `Get-Command` or `command -v` resolves
them. Custom wrapper dispatch scripts remain forbidden.

Use short task strings whenever possible. For long prompts, write the full task
to `$AUDIT/task.md` and dispatch a short instruction that points to that file.
Avoid expanding large prompt files into a shell argument with `$(cat file)` or
PowerShell string interpolation.

- hm is owned by the current host session and must have phase-block authority.
- QUINTE Party A-E are owned by the host SHIMEI overlay and must be five independent native CLI routes with separate artifacts.
- QUINTE Auditor B is owned by the host SHIMEI overlay and must be an independent R3 route, not an R1/R2 substitute.
- MAGI Perspective A-C are optional host SHIMEI overlay routes and must be three independently formed inquiry routes if explicitly bound.
- Implementation or system audit routes are owned by the host SHIMEI overlay and must provide direct runtime evidence for code, tests, logs, or system facts.

## Invariants

- QUINTE R1/R2 is exactly Party A-E as bound by the current host overlay.
- Concrete model/provider choices live in the host overlay, not in the public
  SHIMEI contract.
- QUINTE Auditor B is host-selected and enters only through an explicit SHIMEI
  binding.
- Implementation and system-audit routes are host-selected and must be explicit
  SHIMEI bindings.
- MAGI remains a Hermes Agent Protocol and may be dispatched only when the host
  overlay explicitly binds Perspective A-C.
- Host overlays must record exact executable names, platform-specific paths,
  and entrypoint verification evidence.
- Wrapper dispatch scripts must not exist in active dispatch paths.

## Output Validity

SHIMEI routing succeeds only when the delegate produces a usable answer file.
Process exit status is not enough.

Treat these as failed/unusable dispatches:

- exit `0` with a 0-byte output file
- startup banner only, with no final answer or requested artifact
- a tmux/TUI session that never writes the required `$AUDIT/*.md` file
- provider/network errors in delegate logs, even if the wrapper process exits

Before retrying, inspect the delegate's own log or transcript and keep the
retry inside the same SHIMEI route. Do not replace the configured Auditor B
route with an unbound route.

## Distribution

SHIMEI is authored in HIGHBALL and mirrored into:

- the Hermes technical profile or host overlay
- platform rules repositories

The rules repos are distribution packages, not independent authorities. If the
routing contract changes, update this file first. If only a concrete host
binding changes, update the technical profile, host overlay, and platform
rules.

## Host Overlay Artifact

Host overlays may be represented as JSON and validated with
`bin/validate-shimei-host-overlay.py`. The schema is
`schemas/shimei-host-overlay.schema.json`. Host-specific overlay files should
live in the technical profile or private platform rules, not in this repository.

The overlay records:

- profile reference and platform
- long-prompt policy, including `$AUDIT/task.md` style file references and no
  shell expansion of large prompt bodies
- route id and role
- route type, such as QUINTE party, QUINTE Auditor B, MAGI perspective, or
  implementation audit
- command tokens
- entrypoint kind and verification evidence
- explicit `is_custom_wrapper: false`
- artifact policy, including separate output artifacts and task restatement

The validator enforces QUINTE Party A-E order, exactly one Auditor B when
QUINTE parties are bound, complete MAGI Perspective A-C binding when MAGI is
present, unique route ids, no custom wrappers, and route command alignment with
the verified entrypoint.

Concrete provider names, model ids, endpoints, and credentials remain private
host-overlay data unless a platform rules repository chooses to publish a
host-local convention.

## Verification Commands

Each host overlay must provide verification commands for every active route:

```bash
command -v <party-a-cli>
command -v <party-b-cli>
command -v <party-c-cli>
command -v <party-d-cli>
command -v <party-e-cli>
command -v <auditor-b-cli>
command -v <implementation-cli>
```

```powershell
Get-Command <party-a-cli>,<party-b-cli>,<party-c-cli>,<party-d-cli>,<party-e-cli> -ErrorAction SilentlyContinue
Get-Command <auditor-b-cli>,<implementation-cli> -ErrorAction SilentlyContinue
```
