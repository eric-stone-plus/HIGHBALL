# Retired Process Cleanup Contract

Process cleanup is not an active HIGHBALL responsibility.

QUINTE owns the complete lifecycle of processes it starts, including worker
identity, heartbeats, dead-worker detection, cancellation, cleanup, recovery,
and finalization. Product Router sees one atomic `quinte` process boundary and
must not scan for, kill, or restart QUINTE's internal workers.

Generic host resource management may still exist outside HIGHBALL, but it is
not a QUINTE routing policy and cannot infer ownership from agent names, output
files, providers, models, or phases.

A Linux systemd timer or `Type=oneshot` coordinator is an outer launch and
observation mechanism, not the QUINTE worker service. When it invokes detached
`quinte host start` directly, the worker can remain in the coordinator's
cgroup even though it is in a separate process group. That deployment must use
`KillMode=process` for the coordinator so completion or stopping of the
oneshot does not reap the QUINTE-owned worker. `KillMode=mixed` is safe for the
coordinator only after the worker has been durably delegated to an independent
unit or scope; mixed mode can kill remaining members of the coordinator's own
cgroup and therefore is not a substitute for process mode in the direct-launch
topology.

Disabling or stopping the outer timer/service means “do not run another host
tick”; it does not mean “cancel the active QUINTE run”. Authorized termination
uses `quinte cancel RUN_ID --json`. An interrupted or ambiguous launch uses
`quinte host reconcile --json` before any further launch; reconcile identifies
the durable worker state but does not terminate, resume, or retry it. HIGHBALL
must not turn either deployment operation into internal worker management.

Protected-Write Guard is limited to protected-write validation and residual
closure. Authorization Gate owns external-action authorization. Neither
component owns process cleanup.

This file is retained only to make the retired contract explicit for older
rules distributions.
