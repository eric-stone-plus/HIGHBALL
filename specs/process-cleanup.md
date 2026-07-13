# Retired Process Cleanup Contract

Process cleanup is not an active HIGHBALL responsibility.

QUINTE owns the complete lifecycle of processes it starts, including worker
identity, heartbeats, dead-worker detection, cancellation, cleanup, recovery,
and finalization. SHIMEI sees one atomic `quinte` process boundary and must not
scan for, kill, or restart QUINTE's internal workers.

Generic host resource management may still exist outside HIGHBALL, but it is
not a QUINTE routing policy and cannot infer ownership from agent names, output
files, providers, models, or phases.

BANNIN is now limited to protected-write guarding and residual closure. KENGEN
owns external-action authorization. Neither component owns process cleanup.

This file is retained only to make the retired contract explicit for older
rules distributions.
