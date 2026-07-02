# Process Cleanup

> BANNIN session guard: resource enforcement.

Process cleanup detects and kills stale SHIMEI-dispatched agent processes.
Platform implementations share one contract: detect abandoned agents, resolve
the exact PID, kill only that PID, and log what happened.

## Question

*Still alive? Still needed?* Process cleanup answers the resource-hygiene
question that SHIMEI routing and KENGEN authorization do not cover.

## Position

Process cleanup is a BANNIN sub-component within HIGHBALL's engineering plane.
It runs at the Hermes session level, not inside QUINTE.

- SHIMEI binds aliases to native CLI commands.
- KENGEN decides whether operations are authorized.
- BANNIN enforces runtime checks and process cleanup.

## Contract

All platform implementations must:

1. Detect by output: find agent output files older than `TIMEOUT` minutes with 0 bytes.
2. Match by identity: resolve stale output file to a process PID using platform-specific tooling.
3. Kill by PID: terminate only the specific PID. Never use wildcard image-name termination.
4. Report: log killed processes. Never kill silently.
5. Respect floor: `TIMEOUT` >= 5 minutes. Never kill agents that are still producing output.

## Platform Implementations

### macOS

- Trigger: thermal pressure or stale 0-byte output files.
- Mechanism: match agent CLI signatures and kill precise PIDs where possible.
- Scope: active SHIMEI routes when explicitly dispatched.
- Recovery: wait for thermal recovery before allowing new high-fanout dispatches.

### Windows

- Trigger: `find` agent output files older than `$TIMEOUT_MIN` with 0 bytes.
- Mechanism: resolve agent type to PID, then `taskkill //PID`.
- Scope: same SHIMEI active-agent list.
- Schedule: 5-minute cron cycle.

## Relationship to Other Components

- BANNIN is the parent runtime guard.
- KENGEN authorization decisions are unchanged by cleanup.
- SHIMEI defines the agent identities cleanup may target.
- Cleanup events should be logged for later diagnosis.

## Naming

Formerly "Netsumon". The name was retired because it was opaque and did not
describe the operation. "Process Cleanup" stays literal.

## Ratification

2026-06-22: ratified as a HIGHBALL/BANNIN sub-component. Updated 2026-06-28 to
match the narrowed HIGHBALL boundary, then updated after MAGI runtime bindings
were cleared from active SHIMEI routing.
