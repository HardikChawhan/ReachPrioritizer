# Evaluation

Everything in this document is produced by one script that runs the **production code path** (the analysis engine + the AI model + the backend's `build_findings`):

```bash
python evaluation/scripts/run_experiments.py
# -> evaluation/results/comparative_evaluation.json  (machine-readable, shown on the Model & Research page)
# -> evaluation/results/RESULTS.md                  (tables)
```

Optional inputs:

```bash
bash evaluation/realworld/fetch_realworld.sh          # NodeGoat + DVNA at pinned commits (else skipped)
cd evaluation/baselines/eslint && npm install         # ESLint + eslint-plugin-security baseline (else skipped)
```

## Research questions
- **RQ1:** Does interprocedural call-graph reachability improve the precision of AI-based vulnerability prioritization?
- **RQ2:** Does taint evidence improve detection and ranking beyond pattern rules and function-level ML?

## Benchmarks

| Application | Kind | Files | Functions | Labeled | Vulnerable | Exploitable* |
|---|---|---:|---:|---:|---:|---:|
| vulnerable-app | controlled | 6 | 24 | 9 | 8 | 6 |
| secure-app | controlled (false-positive test) | 6 | 25 | 8 | 0 | 0 |
| mixed-app | controlled (reachable + dead modules) | 7 | 32 | 10 | 5 | 1 |
| express-app | controlled, realistic Express patterns | 12 | 25 | 16 | 9 | 6 |
| OWASP NodeGoat @c5cb68a | real world | 26 | 115 | 5 | 5 | 5 |
| DVNA @9ba473a | real world | 12 | 74 | 6 | 6 | 6 |

\*Exploitable = vulnerable **and** reachable from an active request entry point.

**Ground truth** (`test-applications/*/ground-truth.json`, `evaluation/realworld/*.ground-truth.json`, schema `reachprioritizer-ground-truth/v2`): each entry gives `file`, `function` (or a `line` for anonymous handlers), `is_vulnerable`, `cwe`, `is_reachable` and a note. Reachability means *executable while serving an attacker request*; code that only runs at start-up counts as not reachable. The real-world ground truth lists the documented code-level vulnerabilities only (template XSS, access control and configuration issues are out of scope).

**Corrections to the v1 labels** (also recorded in each file under `corrections_from_v1`):
- mixed-app `fetchExternalReport`: v1 said reachable, but its only caller `handleFetch` is never registered as a route.
- mixed-app `sanitizeString`: v1 said reachable, but it is imported and never called.
- vulnerable-app `renderPage`: missing in v1 although the source marks it vulnerable (CWE-79). Added as vulnerable + unreachable.

## Methodology

**A. Detection (function level).** A detector "flags" a function if it reports anything inside it (a finding's line is mapped to the innermost function). Metrics are computed over labeled functions only.

| Detector | Source |
|---|---|
| ReachPrioritizer taint engine | Static findings from `analyzer/` |
| AI classifier only | Function probability ≥ model threshold |
| v1 prototype regex rules | `evaluation/baselines/legacy_regex_scanner.py` (the v1 rule engine, verbatim) |
| ESLint + eslint-plugin-security | `evaluation/baselines/eslint_security.py` (`plugin:security/recommended`) |

**B. Reachability.** The predicted status `reachable` vs. the ground-truth `is_reachable`, for labeled functions.

**C. Prioritization.** The candidates are one per function: its highest-risk finding, plus AI-flagged functions so that the AI-only scheme is evaluated fairly. Six schemes order the same candidates:

| Id | Scheme | Score |
|---|---|---|
| E0 | Severity only (classic SAST) | severity weight |
| E1 | AI only | AI probability |
| E2 | AI + severity | 0.5·AI + 0.5·severity |
| E3 | AI + reachability | reachability multiplier × AI |
| E4 | AI + severity + reachability (v1 formula) | v1 multiplier × (0.5·AI + 0.5·severity) |
| E5 | **Full ReachPrioritizer** | the production risk score (severity + taint + AI, × reachability) |

Relevance = exploitable (vulnerable **and** reachable). Metrics: P@1/3/5, NDCG@5/10, MAP (average precision), first relevant rank. Ties are broken alphabetically by function id. Means are taken over applications that contain exploitable bugs.

## Results

### A. Detection — controlled applications (pooled: 22 vulnerable, 21 safe)

| Detector | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| **ReachPrioritizer taint engine** | 22 | 0 | 0 | 21 | **1.000** | **1.000** | **1.000** |
| v1 prototype regex rules | 8 | 1 | 14 | 20 | 0.889 | 0.364 | 0.516 |
| AI classifier only | 8 | 7 | 14 | 14 | 0.533 | 0.364 | 0.432 |
| ESLint plugin-security | 5 | 3 | 17 | 18 | 0.625 | 0.227 | 0.333 |

**Real-world recall** (11 documented vulnerabilities): ReachPrioritizer **11/11**, AI classifier 8/11, v1 regex 6/11, ESLint plugin-security 2/11.

### B. Reachability
**54/54** labeled functions are classified correctly across all six applications (TP 38, TN 16, FP 0, FN 0).

### C. Prioritization (mean over the 5 applications with exploitable vulnerabilities)

| Scheme | P@1 | P@3 | P@5 | NDCG@5 | NDCG@10 | MAP |
|---|---:|---:|---:|---:|---:|---:|
| E0 Severity only | 0.600 | 0.733 | 0.760 | 0.816 | 0.865 | 0.813 |
| E1 AI only | 0.200 | 0.200 | 0.160 | 0.171 | 0.388 | 0.322 |
| E2 AI + severity | 0.800 | 0.667 | 0.640 | 0.757 | 0.849 | 0.753 |
| E3 AI + reachability | 0.200 | 0.333 | 0.400 | 0.442 | 0.587 | 0.498 |
| E4 AI + severity + reachability (v1) | 1.000 | 0.867 | 0.760 | 0.948 | 0.991 | 0.972 |
| **E5 Full ReachPrioritizer** | **1.000** | **0.867** | **0.840** | **1.000** | **1.000** | **1.000** |

P@3 and P@5 cannot reach 1.0 in applications with fewer than 3 or 5 exploitable functions (mixed-app has one).

### Interpretation
1. **Taint finds what pattern rules miss.** Real code passes input through variables and across files. Rules that look at a single expression catch only about a quarter to a third of the vulnerabilities.
2. **The AI alone is not enough.** It produces 5 false alarms on secure-app and ranks poorly (MAP 0.32). As a 20% signal it does not hurt.
3. **Reachability fixes the order.** Without it, dead-code vulnerabilities rank first (mixed-app: `exportLegacyBackup`).
4. **Taint evidence separates reachable from exploitable.** It moves startup-only code fed with constants and configuration issues below proven flows (E4 → E5: NDCG@5 0.948 → 1.000).

## Threats to validity
- The controlled applications are small and were written by the project team; express-app was added during v2 development.
- Real-world precision is not measured, because only documented vulnerabilities are labeled. The extra findings were one hardcoded password in a NodeGoat seed script, two md5 uses in DVNA, and a few AI-only suggestions.
- CodeQL was not run (licensing and runtime constraints). Semgrep is supported but was not part of the baselines.

See also: [`docs/RESEARCH_PAPER.md`](RESEARCH_PAPER.md) §9–§12 and the live tables on the **Model & Research** page.
