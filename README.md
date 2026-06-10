# HIGHBALL (ハイボール)

> ハイボール = highball. The constraint layer for AI agent outputs — verdict audit + authorization perimeter.

**HIGHBALL** bundles two complementary constraints on QUINTE debate conclusions. Where [RASHOMON](https://github.com/eric-stone-plus/RASHOMON) asks *why* multi-perspective truth-seeking is necessary and [QUINTE](https://github.com/eric-stone-plus/QUINTE) builds *how* to orchestrate cross-examination, HIGHBALL enforces two questions on every conclusion:

| Question | Component | Role |
|----------|-----------|------|
| *Sound?* | **KANSA** (監査) | Verdict audit — independent second review of every R3 conclusion |
| *May I?* | **KENGEN** (権限) | Authorization perimeter — gates irreversible external writes |

## Relationship

```
RASHOMON (why) ──→ QUINTE (how) ──→ conclusions
     │                                    │
     └── HIGHBALL ──┬─ KANSA (sound?) ────┤
                    └─ KENGEN (may?) ─────┘
```

---

## KANSA (監査) — Verdict Audit

> 監査 = audit, inspection. *Sound?*

KANSA ensures every QUINTE R3 conclusion receives a second, independent review before it becomes actionable. In Phase 6 of every QUINTE round, hm initiates the KANSA audit. A rotating audit consul — matched to the topic domain — independently reviews all R1+R2 evidence and drafts a parallel verdict alongside hm. The two are merged: consensus is adopted, disagreement is surfaced as an annotated dissent.

No single arbiter rules alone. A rotating second auditor prevents any single agent from accumulating imperial authority.

### Audit Consul Matching

| Topic domain | Audit consul |
|---|---|
| Ledger / reporting / economics | omp |
| Contracts / legal / pricing | cc |
| Code / configuration / architecture | cw |
| Protocol / strategy / logic | rx |

---

## KENGEN (権限) — Authorization Perimeter

> 権限 = authority, permission. *May I?*

KENGEN defines the boundary between autonomous agent operations and those requiring explicit user authorization. An agent must not execute irreversible external write operations without explicit user authorization.

### Authorization Perimeter

| Operation class | Examples | Default | Intercept |
|---|---|---|---|
| **push** | `git push`, `git push --force` | blocked | session grep for user authorization |
| **delete** | `rm -rf`, `git reset --hard` | blocked | approvals.mode (Hermes built-in) |
| **config** | config.yaml mutation, `.env` writes | blocked | pre-write validation |

### BANNIN (番人) — The Guard

> 番人 = watchman, guard. The active enforcer.

BANNIN is the active enforcement layer within KENGEN. While KENGEN defines the boundary, BANNIN patrols it — checking every gated command at execution time against the current session's authorization record.

- **Mechanism**: before executing any `git push`, grep the session for user authorization keywords (`push` / `推送` / `推`)
- **Behavior**: unauthorized → BLOCKED. No clarify prompt — the agent has no right to ask. It waits silently.
- **Placement**: runs at the `terminal()` execution layer, not at the debate level. Independent of the four gates.

---

## Design Principle

> A constraint that blocks silently is stronger than one that negotiates. A constraint that rotates is stronger than one that accumulates.

## Prior Art

KANSA and KENGEN originally existed as standalone repositories ([KANSA](https://github.com/eric-stone-plus/KANSA), [KENGEN](https://github.com/eric-stone-plus/KENGEN)). HIGHBALL bundles them as a unified constraint collection.

---

## License

MIT
