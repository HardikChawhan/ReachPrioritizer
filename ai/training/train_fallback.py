"""
Train the TF-IDF + Logistic Regression vulnerability classifier (CPU, ~1 minute).

Reads the repository-disjoint JsVul splits from data/processed/splits/, trains on
the training split, reports validation metrics, evaluates once on the held-out test
split and writes ai/checkpoints/tfidf_fallback/{vectorizer,classifier}.joblib,
metadata.json and evaluation_results.json (the backend reads the test F1 from the
last file to decide which model to use).

Usage (from the project root):
    python ai/training/train_fallback.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SPLITS = PROJECT_ROOT / "data" / "processed" / "splits"
OUT = PROJECT_ROOT / "ai" / "checkpoints" / "tfidf_fallback"
SEED = 42
THRESHOLD = 0.5
MAX_FEATURES = 10_000
NGRAMS = (1, 2)


def load_split(name: str) -> Tuple[List[str], List[int]]:
    path = SPLITS / f"{name}.jsonl"
    if not path.exists():
        sys.exit(f"Missing {path}. Build the dataset first: bash scripts/fetch_dataset.sh")
    texts, labels = [], []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                texts.append(r.get("normalized_source") or "")
                labels.append(int(r.get("label", 0)))
    return texts, labels


def metrics(y_true, proba, threshold: float, with_matrix: bool = False):
    from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                                 recall_score, roc_auc_score)

    pred = [int(p >= threshold) for p in proba]
    out = {
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, proba)),
    }
    if with_matrix:
        out["confusion_matrix"] = confusion_matrix(y_true, pred, labels=[0, 1]).tolist()
        out["num_test_samples"] = len(y_true)
        out["num_vuln_test"] = int(sum(y_true))
    return out


def main() -> None:
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    t0 = time.time()
    x_tr, y_tr = load_split("train")
    x_va, y_va = load_split("validation")
    x_te, y_te = load_split("test")
    print(f"Loaded train={len(x_tr)} (vulnerable {sum(y_tr)}), validation={len(x_va)}, test={len(x_te)}")

    vectorizer = TfidfVectorizer(max_features=MAX_FEATURES, ngram_range=NGRAMS, sublinear_tf=True,
                                 analyzer="word", token_pattern=r"(?u)\b\w+\b")
    X_tr = vectorizer.fit_transform(x_tr)
    clf = LogisticRegression(class_weight="balanced", max_iter=1000, solver="lbfgs", random_state=SEED, C=1.0)
    clf.fit(X_tr, y_tr)

    val = metrics(y_va, clf.predict_proba(vectorizer.transform(x_va))[:, 1], THRESHOLD)
    test = metrics(y_te, clf.predict_proba(vectorizer.transform(x_te))[:, 1], THRESHOLD, with_matrix=True)
    print("Validation: " + "  ".join(f"{k}={v:.4f}" for k, v in val.items()))
    print("Test:       " + "  ".join(f"{k}={v:.4f}" for k, v in test.items() if isinstance(v, float)))

    OUT.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, OUT / "vectorizer.joblib")
    joblib.dump(clf, OUT / "classifier.joblib")
    (OUT / "evaluation_results.json").write_text(json.dumps(
        {"model": "tfidf_logreg", "val_metrics": val, "test_metrics": test}, indent=2), encoding="utf-8")
    (OUT / "metadata.json").write_text(json.dumps({
        "model_type": "tfidf_logreg", "vectorizer_file": "vectorizer.joblib", "classifier_file": "classifier.joblib",
        "max_features": MAX_FEATURES, "ngram_range": list(NGRAMS), "class_weight": "balanced", "threshold": THRESHOLD,
    }, indent=2), encoding="utf-8")
    print(f"Saved to {OUT} in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
