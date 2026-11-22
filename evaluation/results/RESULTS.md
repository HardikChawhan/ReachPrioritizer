# ReachPrioritizer — evaluation results

Generated 2026-11-22T14:46:26.807291+00:00 by `evaluation/scripts/run_experiments.py` (do not edit by hand).
AI model: **TF-IDF + Logistic Regression** (threshold 0.5).

## A. Detection on the controlled applications (function level, pooled)

| Detector | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| ReachPrioritizer taint engine | 22 | 0 | 0 | 21 | 1.000 | 1.000 | 1.000 |
| AI classifier only | 8 | 7 | 14 | 14 | 0.533 | 0.364 | 0.432 |
| v1 prototype regex rules | 8 | 1 | 14 | 20 | 0.889 | 0.364 | 0.516 |
| ESLint plugin-security | 5 | 3 | 17 | 18 | 0.625 | 0.227 | 0.333 |

Recall on the documented vulnerabilities of the real-world projects: ReachPrioritizer taint engine 1.000, AI classifier only 0.727, v1 prototype regex rules 0.545, ESLint plugin-security 0.182.

## B. Reachability (labeled functions, all applications)

Accuracy **1.000**, precision 1.000, recall 1.000, F1 1.000 (TP 38, FP 0, FN 0, TN 16).

## C. Prioritization (mean over applications that contain exploitable vulnerabilities)

| Scheme | P@1 | P@3 | P@5 | NDCG@5 | NDCG@10 | MAP |
|---|---|---|---|---|---|---|
| Severity only (classic SAST) | 0.600 | 0.733 | 0.760 | 0.816 | 0.865 | 0.813 |
| AI probability only | 0.200 | 0.200 | 0.160 | 0.171 | 0.388 | 0.322 |
| AI + severity | 0.800 | 0.667 | 0.640 | 0.757 | 0.849 | 0.753 |
| AI + reachability | 0.200 | 0.333 | 0.400 | 0.442 | 0.587 | 0.498 |
| AI + severity + reachability (v1 formula) | 1.000 | 0.867 | 0.760 | 0.948 | 0.991 | 0.972 |
| Full ReachPrioritizer (severity + taint + AI + reachability) | 1.000 | 0.867 | 0.840 | 1.000 | 1.000 | 1.000 |

## Per application

| Application | Files | Functions | Labeled | Vulnerable | Exploitable | Taint F1 / recall | Reachability acc. | E5 P@1 | E5 MAP |
|---|---|---|---|---|---|---|---|---|---|
| vulnerable-app | 6 | 24 | 9 | 8 | 6 | 1.000 | 1.000 | 1.000 | 1.000 |
| secure-app | 6 | 25 | 8 | 0 | 0 | 1.000 | 1.000 | – | – |
| mixed-app | 7 | 32 | 10 | 5 | 1 | 1.000 | 1.000 | 1.000 | 1.000 |
| express-app | 12 | 25 | 16 | 9 | 6 | 1.000 | 1.000 | 1.000 | 1.000 |
| NodeGoat | 26 | 115 | 5 | 5 | 5 | recall 1.000 | 1.000 | 1.000 | 1.000 |
| dvna | 12 | 74 | 6 | 6 | 6 | recall 1.000 | 1.000 | 1.000 | 1.000 |

Ties in a ranking are broken alphabetically by function id (neutral). Unlabeled functions in the real-world projects count as non-relevant, so their precision figures are lower bounds.
