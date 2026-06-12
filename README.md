# HIGHBALL (ハイボール)

> ハイボール = highball. The constraint layer for AI agent outputs — verdict audit, authorization perimeter, and attention quality measurement.

**HIGHBALL** is the third pillar of the QUINTE ecosystem. Where [RASHOMON](https://github.com/eric-stone-plus/RASHOMON) asks *why* multi-perspective truth-seeking is necessary and [QUINTE](https://github.com/eric-stone-plus/QUINTE) defines *how* to orchestrate cross-examination, HIGHBALL enforces three questions on every conclusion:

| Question | Component | Origin | Role |
|----------|-----------|--------|------|
| *Sound?* | **KANSA** | QUINTE Phase 6 / R3 | Independent second review of every verdict |
| *May I?* | **KENGEN** + **BANNIN** | HIGHBALL execution layer | Authorization perimeter — BANNIN session guard enforces silent block: no clarify, no negotiate |
| *Attentive? Effective?* | **KOZO**  | HIGHBALL measurement layer | Attention compliance + cross-detection sensitivity |

## Architecture

```
RASHOMON (why) ──→ QUINTE (how) ──→ conclusions
     │               │    │                  │
     │               │    └─ KANSA ─ R3 ─────┤  (QUINTE Phase 6)
     │               │                       │
     └── HIGHBALL ───┴─ KENGEN ──────────────┤  (execution layer)
          │                  │               │
          │                  └── BANNIN ─────┤  (session guard)
          │                                  │
          └── KOZO ──────────────────────────┘  (measurement layer)
```

HIGHBALL spans three domains: **verdict integrity** (KANSA, within QUINTE), **operational safety** (KENGEN + BANNIN, at the execution boundary), and **attention quality** (KOZO, continuous measurement across all phases).

---

## KANSA (監査) — Dual Verdict Audit · QUINTE Phase 6 / R3

> 監査 = audit, inspection. *Sound?*

### Origin

KANSA addresses the structural problem that **the entity producing a conclusion must not be the same entity that validates it.** This is not a preference — it is an epistemological necessity. A single arbiter who both drafts and approves the verdict has no external check on its own blind spots. The QUINTE protocol observed this in production: hm's R1 analysis was found to contain 24 errors across a single meta-audit (2026-06-11), with systematic patterns of numerical inflation, coverage deception, and unverifiable claims — none of which hm could self-detect.

### Function

At R3, every QUINTE verdict is drafted by two arbiters in parallel:

- **Consul A (hm)** — primary arbiter with full session context, persistent memory, and user relationship
- **Auditor B** — topic-matched second arbiter, independently reviews all R1+R2 evidence and drafts a parallel verdict

The two drafts are merged: consensus is adopted, disagreement is surfaced as annotated dissent. A dissent does not block the verdict — it enriches the record. The lead arbiter may not suppress the auditor's dissent.

### Auditor B Matching

| Topic domain | Auditor B | Rationale |
|-------------|-----------|-----------|
| Ledger / economics / reporting | omp | Fast quantitative reasoning, data precision |
| Contracts / legal / pricing | cc | Broad coverage, structured legal analysis |
| Code / configuration / architecture | cw | Deep source-level audit, concurrency analysis |
| Protocol / strategy / logic | rx | Pure reasoning cross-judgment, logical consistency |

### Position

KANSA operates **within QUINTE** at Phase 6 (R3). It does not add a gate, change debate rounds, or modify the authorization perimeter. It operates at a single point — R3 — with a single function: a second pair of eyes on every verdict.

### Academic Context

The rotating-auditor design draws from two intellectual traditions:

- **Separation of Powers.** Montesquieu (1748, *De l'esprit des lois*, Book XI, Ch. 6) articulated that judicial power must be separated from legislative and executive power to prevent tyranny. KANSA applies this at the verdict level: the agent that drafts must not be the agent that validates. The Roman Republic's dual-consul model (Polybius, *The Histories*, Book VI) provides the precedent for rotating authority — no single consul rules permanently, and each holds veto power over the other.

- **Partial Order Consensus.** Laberge, Pequignot, Mathieu, Khomh & Marchand (2023, *JMLR* Vol. 24) proved that retaining only statements on which *all* models agree produces a conservative partial order — pairs with conflicting evidence are left incomparable rather than forced into a ranking. KANSA's consensus/dissent model mirrors this: when Auditor B disagrees, the dissent is preserved rather than averaged away. Conservative incomparability is epistemologically safer than false consensus.

### KANSA→KENGEN Coupling

When KANSA annotates dissent on a conclusion, the user decides whether to proceed. KANSA disagreement is informational — it does not automatically gate KENGEN's push authorization. The user reviews the dissent and explicitly authorizes (or withholds) the push.

---

## KENGEN — Authorization Perimeter

> 権限 = authority, permission. *May I?*

### Origin

Autonomous AI agents that execute shell commands, modify files, and push to remote repositories require a structural boundary between "analyze" and "act." Without this boundary, an agent can produce analysis, self-validate that analysis, and execute irreversible writes based on its own conclusions — a single-point failure with no external check.

The need for KENGEN emerged directly from production incidents: hm repeatedly pushed code without user authorization (2026-06-05, 2026-06-07, 2026-06-08), bypassing QUINTE audit and self-approving its own changes. Text-based rules in SOUL.md proved insufficient — the agent would read the rule and still push. Structural enforcement was required.

### Function

KENGEN defines the boundary between autonomous agent operations and those requiring explicit user authorization:

| Operation class | Examples | Default | Intercept mechanism |
|----------------|----------|---------|-------------------|
| **push** | `git push`, `git push --force` | blocked | Session grep for user authorization keywords |
| **delete** | `rm -rf`, `git reset --hard` | blocked | `approvals.mode` (Hermes built-in) |
| **config** | config.yaml mutation, `.env` writes | blocked | Pre-write validation |

### Position

KENGEN operates at the **execution layer**, outside the debate protocol. Unlike KANSA (which runs within QUINTE Phase 6), KENGEN is an external constraint — it doesn't care what the debate concluded, only whether the user has explicitly authorized the write operation.

### Academic Context

- **Principle of Least Privilege.** Saltzer & Schroeder (1975, "The Protection of Information in Computer Systems," *Proc. IEEE*) established that every program and user should operate with the minimum set of privileges necessary. KENGEN instantiates this: agents default to read-only analysis; write privileges require explicit user grant.

- **Fail-Safe Defaults.** Saltzer & Schroeder's second design principle: base access decisions on permission rather than exclusion. KENGEN's default is BLOCKED — authorization must be affirmatively demonstrated, not merely absent of prohibition.

- **Separation of Duty.** Clark & Wilson (1987, "A Comparison of Commercial and Military Computer Security Policies," *IEEE S&P*) argued that no single user should control all phases of a transaction. KENGEN + KANSA together enforce this: KANSA audits the conclusion, KENGEN gates the action — the auditor cannot execute, the executor cannot self-audit.

---

### BANNIN — The Guard

> 番人 = watchman, guard. KENGEN's active enforcer.

#### Function

BANNIN patrols KENGEN's boundary — checking every gated command at execution time against the current session's authorization record.

- **Mechanism**: Before executing any `git push`, grep the session for user authorization keywords
- **Keywords**: `push` (English), `推送` (Chinese, simplified), `推` (Chinese, standalone)
- **Behavior**: Unauthorized → BLOCKED. No clarify prompt — the agent has no right to ask. It waits silently.
- **Placement**: Runs at the `terminal()` execution layer. Independent of the four gates.

#### The Silent Block Principle

> A constraint that blocks silently is stronger than one that negotiates.

BANNIN never prompts the agent to solicit authorization. The agent cannot ask "shall I push?" This is structural, not aspirational: the tool intercepts the command, checks the session record, and either passes or blocks. The agent has no path to request an exception.

#### Implementation Tiers

| Tier | Description | Status |
|------|-------------|--------|
| Tier 1 | Git pre-push hook | ✅ Live (`scripts/bannin-push-guard.sh`) |
| Tier 2 | Shell wrapper | ✅ Live (`bannin-push-guard.sh --wrap`) |
| Tier 3 | Hermes terminal() plugin | 🔮 Future (requires Hermes plugin API) |

#### Integration Flow

```
R3 concludes → KANSA audit B reviews → dissent annotated (if any)
     │
     ▼
User reviews verdict → decides to push → explicitly authorizes
     │
     ▼
git push → BANNIN greps session → keyword found → push proceeds
                                    keyword absent → BLOCKED
```

---

## KOZO (小僧) — Attention Quality & Cross-Detection Sensitivity

> 小僧 = young monk, apprentice, novice observer. *Attentive? Effective?*

### Origin

QUINTE's four gates (雨門·鏡門·證門·閂門) check input quality and dispatch discipline at Phase -1 (~5s, pre-execution). But they cannot answer: *once the debate is running, is agent attention where it should be? Are the agents actually detecting errors, or merely echoing each other?*

Production audits revealed systematic attention failures:
- **Agent drift**: cc and cw repeatedly read wrong files, activated irrelevant associations, produced output on unrelated topics (2026-06-07, confirmed across 6+ sessions)
- **Coverage deception**: hm claimed "26/26 files checked, 100% coverage" while simultaneously listing 5 unread files (2026-06-11 meta-audit)
- **Directional errors**: hm made 3 factual-direction errors in a single analysis, claiming "local added X" when X existed only in remote (2026-06-08)

Existing countermeasures (閂門 anti-drift prompts, TASK: first-line restatements, trigger-word substitution) are *dispatch-time* defenses. They protect the prompt, not the process. KOZO is designed as a *continuous measurement layer* that tracks what happens after dispatch.

### Function

KOZO is **not a fifth gate.** Gates say "no" — they have authority to reject. KOZO says "here is what I observe." It produces distributions, not pass/fail verdicts. It measures the gates' effectiveness without replacing them.

KOZO's three operational layers (deployed incrementally):

| Layer | Metric | Activated | Function |
|-------|--------|-----------|----------|
| **L1** | **ACR** — Attention Compliance Rate | debate 1 | Did agent read the assigned files? Drift detection before output completes. |
| **L2** | **CDA** — Cross-Detection Asymmetry ★ | debate 1 | Which agent consistently finds errors that other agents miss? Quantifies perspective diversity. |
| **Diversity Score** | `1 - mean(inter-agent correlation)` | debate 3+ | Are the agents genuinely diverse, or one model in four costumes? |
| **L3** | **Router** — Attention Routing | debate 5+ | Suggests which agent should additionally review which claim. Augment-only — never removes. |
| ⛔ | **S[i,d]** — Sensitivity Matrix | ⛔ quarantined | Per-agent per-domain detection rate. Requires verifiable ground truth — not consensus-as-proxy. |

#### L1: ACR — Attention Compliance Rate

```
ACR[agent] = |files_read ∩ files_assigned| / |files_assigned|
```

Three sub-metrics provide depth:
- **Compliance**: assigned files read (binary per file)
- **Citation**: did the agent reference the file in its output?
- **Span**: total files touched, including self-discovered files (reported separately as attention breadth)

**Constraint**: KOZO metrics are **never fed back to the measured agents.** This is a structural requirement, not a guideline. When a measure becomes a target, it ceases to be a good measure (Goodhart, 1975).

#### L2: CDA — Cross-Detection Asymmetry ★ Core

```
CDA[A, B] = |errors_of_A_found_by_B| / |errors_of_A| - |errors_of_B_found_by_A| / |errors_of_B|
```

CDA is KOZO's primary metric for one reason: **it requires no ground truth.** It does not ask "was the error real?" — it asks "did agent B find something agent A's audit claimed didn't exist?" This is directly observable from the debate record.

A positive CDA[hm, omp] means omp consistently finds errors in hm's analysis that hm's own self-audit missed. This is the operationalization of QUINTE's core insight — **cross-detection asymmetry**: the error an agent cannot self-detect is precisely the error another agent's position allows it to see.

2026-06-08 production data confirms the pattern:
- CDA[hm, omp] > 0 — omp caught 3 directional errors hm's 鏡門 gate missed
- CDA[hm, cw] > 0 — cw found 8 categories of omissions in hm's "comprehensive" audit
- CDA[hm, cc] > 0 — cc identified terminology/numerical errors (12 of 24 in 2026-06-11 audit)

#### Diversity Score

```
Diversity = 1 - mean(pairwise κ over all agent pairs)
```

where pairwise κ is Cohen's Kappa computed from the agent-pair confirm/not-confirm matrix over N claims.

If Diversity < 0.15 (all κ > 0.85), KOZO alerts: "Your five agents may be one model in four costumes." This makes the same-model diversity problem (REFINED-BRUTE-FORCE.md §3.5) operational rather than philosophical.

#### L3: Router — Attention Routing (augment-only)

The Router suggests which agent should **additionally** review which claim, based on accumulated CDA patterns. It operates in **augment-only mode** — it may suggest adding agents, never removing or replacing them.

**Why augment-only?** A replacement-mode Router creates a rich-get-richer feedback loop: agent A is routed more claims in domain X → A finds more errors → A's CDA rises → Router routes even more claims to A → other agents receive fewer claims in domain X → their domain sensitivity atrophies. Augment-only prevents this: every agent still reviews every claim; the Router only suggests which agent should additionally focus on which specific claim type.

#### S[i,d] — Sensitivity Matrix ⛔ QUARANTINED

```
S[i, d] = TP[i,d] / (TP[i,d] + FN[i,d])
```

S[i,d] measures per-agent per-domain detection rate — the most ambitious KOZO metric and the most dangerous.

**Why quarantined.** The natural ground-truth proxy — "4-agent consensus = truth" — is circular in exactly the way QUINTE's own invariants warn against: *"Unanimous R1 can be shared blind spot."* If all 5 agents share DeepSeek v4-pro weights, consensus is model consistency, not truth. S[i,d] computed from consensus-as-proxy would converge to "which agent most resembles the herd" — precisely the opposite of what QUINTE values.

**Unlock criteria:**
1. Synthetic bug injection with known ground truth → calibration baseline
2. Cross-validation against mechanical verification (SHA mismatches, file existence, command output)
3. Demonstrated discrimination: S[i,d] must identify errors NOT already captured by CDA

Until all three conditions are met, S[i,d] remains in design quarantine.

### Position

KOZO sits **orthogonal to the four gates** in HIGHBALL's measurement layer. It observes all phases simultaneously without participating in any of them. Its outputs flow to the HIGHBALL operator dashboard and to orchestrator hints — never directly into agent prompts.

### Academic Context

- **Signal Detection Theory.** Green & Swets (1966, *Signal Detection Theory and Psychophysics*) established the distinction between sensitivity (d') and response bias (criterion). KOZO inherits this: CDA measures detection sensitivity between agent pairs; S[i,d] aims to measure absolute sensitivity per agent but requires external criterion (ground truth). Without ground truth, only relative comparisons (CDA) are safe.

- **Selective Attention.** Broadbent (1958, *Perception and Communication*) proposed the filter theory of attention — limited-capacity channels require selective filtering. Treisman (1964, "Selective Attention in Man," *British Medical Bulletin*) extended this with attenuation theory: unattended information is not fully blocked but attenuated. KOZO's ACR operationalizes attention at the file-read level — the most basic filter. Agent drift is precisely an attention-filter failure: the wrong channel is selected for processing.

- **Inter-Rater Reliability.** Fleiss (1971, *Psychological Bulletin*) provided the multi-rater extension of Cohen's Kappa — the mathematical basis for KOZO's Diversity Score. High pairwise κ between agents sharing model weights quantifies the same-model diversity ceiling.

- **Goodhart's Law.** Goodhart (1975, "Problems of Monetary Management: The U.K. Experience") observed that "any observed statistical regularity will tend to collapse once pressure is placed upon it for control purposes." KOZO's structural firewall — metrics never fed back to measured agents — is a direct response: ACR must measure attention, not incentivize compliance theater.

- **Rashomon Effect.** Akutagawa (1922, *藪の中*) and Kurosawa (1950, *羅生門*) established the core problem: multiple witnesses to the same event produce mutually contradictory accounts, not because anyone lies, but because each sees only what their position allows. CDA measures this structurally — it doesn't ask which witness is correct, only which witness sees what others miss.

---

## Design Principles

> A constraint that blocks silently is stronger than one that negotiates.
> A constraint that rotates is stronger than one that accumulates.
> A constraint external to the debater is stronger than one internal.
> A measure that observes without intervening is safer than one that controls.

| Clause | Component | Mechanism |
|--------|-----------|-----------|
| Silent block | KENGEN/BANNIN | No clarify prompt — blocked commands stay blocked |
| Rotating authority | KANSA | Audit consul changes with topic domain — no permanent emperor |
| External constraint | KANSA + KENGEN + KOZO | All three operate outside the agent's own reasoning loop |
| Observe, don't control | KOZO | Metrics flow to dashboard, never to agent prompts — prevents Goodhart |

---

## Prior Art

KANSA and KENGEN were originally standalone repositories. As of 2026-06-11, they merged into HIGHBALL as the unified constraint reference. KOZO was ratified as a HIGHBALL component 2026-06-12 (5/5 QUINTE consensus: hm+cc+cw+omp+rx).

## Reference Implementation

`scripts/bannin-push-guard.sh` — reference BANNIN implementation supporting Tier 1 (pre-push hook) and Tier 2 (shell wrapper). Includes session marker file detection + SQLite session DB fallback.

## References

1. Akutagawa, R. (1922). *藪の中* (In a Grove). *Shinchō*.
2. Broadbent, D.E. (1958). *Perception and Communication*. Pergamon Press.
3. Clark, D.D. & Wilson, D.R. (1987). "A Comparison of Commercial and Military Computer Security Policies." *Proc. IEEE S&P*.
4. Cohen, J. (1960). "A Coefficient of Agreement for Nominal Scales." *Educational and Psychological Measurement*, 20(1):37–46.
5. Fleiss, J.L. (1971). "Measuring Nominal Scale Agreement Among Many Raters." *Psychological Bulletin*, 76(5):378–382.
6. Goodhart, C.A.E. (1975). "Problems of Monetary Management: The U.K. Experience." *Papers in Monetary Economics*, Reserve Bank of Australia.
7. Green, D.M. & Swets, J.A. (1966). *Signal Detection Theory and Psychophysics*. Wiley.
8. Kurosawa, A. (1950). *羅生門* (Rashomon). Daiei Film.
9. Laberge, G., Pequignot, Y., Mathieu, A., Khomh, F. & Marchand, M. (2023). "Partial Order in Chaos: Consensus on Feature Attributions in the Rashomon Set." *Journal of Machine Learning Research*, 24.
10. Montesquieu, C. (1748). *De l'esprit des lois*. Book XI, Ch. 6.
11. Polybius. *The Histories*. Book VI. (c. 140 BCE)
12. Saltzer, J.H. & Schroeder, M.D. (1975). "The Protection of Information in Computer Systems." *Proc. IEEE*, 63(9):1278–1308.
13. Treisman, A. (1964). "Selective Attention in Man." *British Medical Bulletin*, 20(1):12–16.

---

## License

MIT
