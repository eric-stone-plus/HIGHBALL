# HIGHBALL (ハイボール)

> ハイボール = highball. The constraint layer for AI agent outputs — verdict audit + authorization perimeter.

**HIGHBALL** documents the constraint layer around [QUINTE](https://github.com/eric-stone-plus/QUINTE) debate conclusions. Where [RASHOMON](https://github.com/eric-stone-plus/RASHOMON) asks *why* multi-perspective truth-seeking is necessary and [QUINTE](https://github.com/eric-stone-plus/QUINTE) builds *how* to orchestrate cross-examination, HIGHBALL enforces two questions on every conclusion:

| Question | Component | Owner | Role |
|----------|-----------|-------|------|
| *Sound?* | **KANSA** (監査) | QUINTE Phase 6 | Verdict audit — independent second review of every R3 conclusion |
| *May I?* | **KENGEN** (権限) | HIGHBALL | Authorization perimeter — gates irreversible external writes |

> **Important**: KANSA is a QUINTE-internal component (Phase 6/R3). HIGHBALL documents and promotes it but does not own it. KENGEN is the only genuinely independent HIGHBALL component, operating at the execution layer outside the debate protocol.

## Relationship

```
RASHOMON (why) ──→ QUINTE (how) ──→ conclusions
     │               │    │                  │
     │               │    └─ KANSA ─ R3 ─────┤  (QUINTE Phase 6)
     │               │                       │
     └── HIGHBALL ───┴─ KENGEN ──────────────┘  (execution layer)
                            │
                            └── BANNIN (guard)
```

KANSA runs **within** QUINTE during the debate. KENGEN runs **outside** QUINTE after the debate, at the execution layer. HIGHBALL spans both — documenting QUINTE's internal constraint (KANSA) and providing the external one (KENGEN).

---

## KANSA (監査) — Verdict Audit · QUINTE Phase 6

> 監査 = audit, inspection. *Sound?*

KANSA is **Phase 6 (R3) of the QUINTE debate protocol**. It ensures every R3 conclusion receives a second, independent review before it becomes actionable. hm initiates the KANSA audit. A rotating audit consul (監査 B) — matched to the topic domain by an independent registry — independently reviews all R1+R2 evidence and drafts a parallel verdict alongside hm. hm holds synchronous veto across all phases. The two verdicts are merged: consensus is adopted, disagreement is surfaced as an annotated dissent.

No single arbiter rules alone. A rotating second auditor prevents any single agent from accumulating imperial authority. The audit consul changes with the topic — no permanent emperor, no unchallenged verdict.

KANSA is orthogonal to the RASHOMON→QUINTE pipeline. It does not add a gate, change debate rounds, or modify the authorization perimeter. It operates at a single point — R3 — with a single function: a second pair of eyes on every verdict.

### Audit Consul Matching

| Topic domain | Audit consul |
|---|---|
| Ledger / reporting / economics | omp |
| Contracts / legal / pricing | cc |
| Code / configuration / architecture | cw |
| Protocol / strategy / logic | rx |

### KANSA→KENGEN Coupling

When KANSA annotates dissent on a conclusion, the user decides whether to proceed. KANSA disagreement is informational — it does not automatically gate KENGEN's push authorization. The user reviews the dissent and explicitly authorizes (or withholds) the push.

---

## KENGEN (権限) — Authorization Perimeter

> 権限 = authority, permission. *May I?*

**The Rule**: An agent must not execute irreversible external write operations without explicit user authorization.

KENGEN defines the boundary between autonomous agent operations and those requiring explicit user authorization. It is the operational safety companion to RASHOMON, QUINTE, and KANSA — operating at the execution layer outside the debate protocol.

### Authorization Perimeter

| Operation class | Examples | Default | Intercept |
|---|---|---|---|
| **push** | `git push`, `git push --force` | blocked | session grep for user authorization |
| **delete** | `rm -rf`, `git reset --hard` | blocked | approvals.mode (Hermes built-in) |
| **config** | config.yaml mutation, `.env` writes | blocked | pre-write validation |

### Authorization Keywords

BANNIN checks for these keywords in the current Hermes session (since last session start or `/new`):
- `push` (English)
- `推送` (Chinese, simplified)
- `推` (Chinese, standalone — only when preceding context indicates push intent)

### BANNIN (番人) — The Guard

> 番人 = watchman, guard. The active enforcer.

BANNIN patrols KENGEN's boundary — checking every gated command at execution time against the current session's authorization record.

- **Mechanism**: before executing any `git push`, grep the session for user authorization keywords
- **Behavior**: unauthorized → BLOCKED. No clarify prompt — the agent has no right to ask. It waits silently.
- **Placement**: runs at the `terminal()` execution layer, not at the debate level. Independent of the four gates.

### Implementation Tiers

| Tier | Description | Status |
|------|-------------|--------|
| Tier 1 | Git pre-push hook | ✅ Live (`scripts/bannin-push-guard.sh`) |
| Tier 2 | Shell wrapper | ✅ Live (`bannin-push-guard.sh --wrap`) |
| Tier 3 | Hermes terminal() plugin | 🔮 Future (requires Hermes plugin API) |

Tier 1+2 catch most `git push` operations. Tier 3 is the architectural target — full integration at the Hermes execution layer.

### Integration Flow

```
R3 concludes → KANSA audit B reviews → dissent annotated (if any)
     │
     ▼
User reviews verdict → decides to push → says "push" / "推"
     │
     ▼
git push → BANNIN greps session → keyword found → push proceeds
                                    keyword absent → BLOCKED
```

---

## Design Principle

> A constraint that blocks silently is stronger than one that negotiates.
> A constraint that rotates is stronger than one that accumulates.
> A constraint external to the debater is stronger than one internal.

- Clause 1 → KENGEN/BANNIN: silent block, no negotiation
- Clause 2 → KANSA: rotating audit consul prevents imperial drift
- Clause 3 → Both: KANSA and KENGEN operate outside hm's reasoning loop — the author does not audit the author

## Prior Art

KANSA and KENGEN were originally standalone repositories. As of 2026-06-11, they are merged into HIGHBALL as the unified constraint reference. The original repos are archived.

### Reference Implementation

`scripts/bannin-push-guard.sh` — reference BANNIN implementation supporting Tier 1 (pre-push hook) and Tier 2 (shell wrapper). Includes session marker file detection + SQLite session DB fallback.

---

## License

MIT
