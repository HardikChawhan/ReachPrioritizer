"""
Fine-tune CodeBERT (or any RoBERTa-style code model) as a function-level
JavaScript vulnerability classifier on the repository-disjoint JsVul splits.

GPU-optimised:
  * bf16 (RTX 30xx/40xx/50xx) or fp16 automatic mixed precision
  * dynamic padding (much faster than padding every sample to 512 tokens)
  * class-weighted loss for the 9:1 imbalance
  * early stopping on validation F1
  * decision threshold tuned on the validation split, then applied to test
  * writes train_meta.json with test metrics -> the backend auto-selects the
    model only if its test F1 beats the TF-IDF baseline

Usage (from the project root):
    python ai/training/train_codebert.py                    # full training (GPU)
    python ai/training/train_codebert.py --quick-test       # 2-minute pipeline check
    python ai/training/train_codebert.py --model microsoft/unixcoder-base

See docs/AI_MODEL_AND_TRAINING.md for installation on RTX 4060 / 5070 Ti laptops.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SPLITS = PROJECT_ROOT / "data" / "processed" / "splits"
CKPT_ROOT = PROJECT_ROOT / "ai" / "checkpoints"
OUT_DIR = CKPT_ROOT / "codebert_vuln_classifier"


def parse_args():
    p = argparse.ArgumentParser(description="Fine-tune CodeBERT for JS vulnerability detection")
    p.add_argument("--model", default="microsoft/codebert-base")
    p.add_argument("--epochs", type=int, default=4)
    p.add_argument("--batch-size", type=int, default=16, help="per-step batch (lower to 8 if you run out of VRAM)")
    p.add_argument("--grad-accum", type=int, default=2, help="gradient accumulation steps (effective batch = batch * accum)")
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--warmup", type=float, default=0.06)
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument("--patience", type=int, default=2, help="early-stopping patience (epochs)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--num-workers", type=int, default=0 if os.name == "nt" else 2)
    p.add_argument("--no-amp", action="store_true", help="disable mixed precision")
    p.add_argument("--quick-test", action="store_true", help="tiny run to check the pipeline (never auto-selected)")
    p.add_argument("--output", default=str(OUT_DIR))
    return p.parse_args()


def load_split(name: str, limit: Optional[int] = None) -> Tuple[List[str], List[int]]:
    sys.path.insert(0, str(PROJECT_ROOT))
    from ai.inference.predictor import normalize_source

    path = SPLITS / f"{name}.jsonl"
    if not path.exists():
        raise SystemExit(f"Missing {path}. Run `npm run phase1` in the project root to rebuild the dataset splits.")
    texts, labels = [], []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            texts.append(normalize_source(r.get("normalized_source") or r.get("original_source") or ""))
            labels.append(int(r.get("label", 0)))
            if limit and len(texts) >= limit:
                break
    return texts, labels


def best_threshold(probs, labels) -> Tuple[float, float]:
    from sklearn.metrics import f1_score

    best_t, best_f = 0.5, -1.0
    for i in range(5, 96):
        t = i / 100
        f = f1_score(labels, [int(p >= t) for p in probs], zero_division=0)
        if f > best_f:
            best_t, best_f = t, f
    return best_t, best_f


def metrics(probs, labels, threshold: float) -> Dict:
    from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score)

    pred = [int(p >= threshold) for p in probs]
    out = {
        "threshold": threshold,
        "accuracy": float(accuracy_score(labels, pred)),
        "precision": float(precision_score(labels, pred, zero_division=0)),
        "recall": float(recall_score(labels, pred, zero_division=0)),
        "f1": float(f1_score(labels, pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(labels, pred, labels=[0, 1]).tolist(),
        "num_samples": len(labels),
        "num_vulnerable": int(sum(labels)),
    }
    if len(set(labels)) > 1:
        out["roc_auc"] = float(roc_auc_score(labels, probs))
        out["pr_auc"] = float(average_precision_score(labels, probs))
    return out


def main():
    args = parse_args()
    import numpy as np
    import torch
    from torch.utils.data import DataLoader
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding,
                              get_linear_schedule_with_warmup)

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    gpu_name = torch.cuda.get_device_name(0) if device.type == "cuda" else None
    use_amp = device.type == "cuda" and not args.no_amp
    amp_dtype = torch.bfloat16 if (use_amp and torch.cuda.is_bf16_supported()) else torch.float16
    print(f"Device: {device}{' (' + gpu_name + ')' if gpu_name else ''} | mixed precision: "
          f"{str(amp_dtype).replace('torch.', '') if use_amp else 'off'}")
    if device.type == "cpu" and not args.quick_test:
        print("WARNING: no CUDA GPU detected — full training on CPU takes many hours. "
              "Install the CUDA build of PyTorch (see docs/AI_MODEL_AND_TRAINING.md).")

    limit_train, limit_eval = (400, 200) if args.quick_test else (None, None)
    epochs = 1 if args.quick_test else args.epochs
    t0 = time.time()
    tr_x, tr_y = load_split("train", limit_train)
    va_x, va_y = load_split("validation", limit_eval)
    te_x, te_y = load_split("test", limit_eval)
    print(f"Loaded train={len(tr_x)} (vulnerable {sum(tr_y)}), val={len(va_x)}, test={len(te_x)} in {time.time() - t0:.1f}s")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2).to(device)

    def encode(texts, labels):
        enc = tokenizer(texts, truncation=True, max_length=args.max_length)
        return [{"input_ids": enc["input_ids"][i], "attention_mask": enc["attention_mask"][i], "labels": labels[i]}
                for i in range(len(texts))]

    t0 = time.time()
    train_ds, val_ds, test_ds = encode(tr_x, tr_y), encode(va_x, va_y), encode(te_x, te_y)
    print(f"Tokenized in {time.time() - t0:.1f}s")
    collate = DataCollatorWithPadding(tokenizer)
    pin = device.type == "cuda"
    train_dl = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, collate_fn=collate, num_workers=args.num_workers, pin_memory=pin)
    val_dl = DataLoader(val_ds, batch_size=args.batch_size * 2, shuffle=False, collate_fn=collate, num_workers=args.num_workers, pin_memory=pin)
    test_dl = DataLoader(test_ds, batch_size=args.batch_size * 2, shuffle=False, collate_fn=collate, num_workers=args.num_workers, pin_memory=pin)

    pos = max(1, sum(tr_y))
    neg = max(1, len(tr_y) - pos)
    class_weight = torch.tensor([1.0, neg / pos], dtype=torch.float, device=device)
    loss_fn = torch.nn.CrossEntropyLoss(weight=class_weight)
    no_decay = ("bias", "LayerNorm.weight")
    params = [
        {"params": [p for n, p in model.named_parameters() if not any(nd in n for nd in no_decay)], "weight_decay": args.weight_decay},
        {"params": [p for n, p in model.named_parameters() if any(nd in n for nd in no_decay)], "weight_decay": 0.0},
    ]
    optimizer = torch.optim.AdamW(params, lr=args.lr)
    steps = max(1, math.ceil(len(train_dl) / args.grad_accum) * epochs)
    scheduler = get_linear_schedule_with_warmup(optimizer, int(args.warmup * steps), steps)
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp and amp_dtype == torch.float16)

    def predict(dl) -> List[float]:
        model.eval()
        out: List[float] = []
        with torch.no_grad():
            for batch in dl:
                batch = {k: v.to(device, non_blocking=True) for k, v in batch.items() if k != "labels"}
                with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=use_amp):
                    logits = model(**batch).logits
                out.extend(torch.softmax(logits.float(), dim=-1)[:, 1].cpu().tolist())
        return out

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    history = []
    best = {"f1": -1.0, "epoch": 0, "threshold": 0.5}
    bad_epochs = 0
    started = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        t_ep = time.time()
        running, n = 0.0, 0
        optimizer.zero_grad(set_to_none=True)
        for step, batch in enumerate(train_dl, 1):
            batch = {k: v.to(device, non_blocking=True) for k, v in batch.items()}
            labels = batch.pop("labels")
            with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=use_amp):
                logits = model(**batch).logits
            loss = loss_fn(logits.float(), labels) / args.grad_accum
            scaler.scale(loss).backward()
            if step % args.grad_accum == 0 or step == len(train_dl):
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
            running += loss.item() * args.grad_accum
            n += 1
            if step % 100 == 0 or step == len(train_dl):
                el = time.time() - t_ep
                eta = el / step * (len(train_dl) - step)
                print(f"  epoch {epoch} step {step}/{len(train_dl)} loss {running / n:.4f} | "
                      f"{el / 60:.1f} min elapsed, ~{eta / 60:.1f} min left in epoch", flush=True)

        val_probs = predict(val_dl)
        thr, _ = best_threshold(val_probs, va_y)
        vm = metrics(val_probs, va_y, thr)
        rec = {"epoch": epoch, "train_loss": round(running / max(1, n), 4), "val": vm, "epoch_minutes": round((time.time() - t_ep) / 60, 2)}
        history.append(rec)
        print(f"Epoch {epoch}: train_loss={rec['train_loss']} val_f1={vm['f1']:.4f} (threshold {thr:.2f}) "
              f"P={vm['precision']:.3f} R={vm['recall']:.3f} AUC={vm.get('roc_auc', 0):.3f}")
        if vm["f1"] > best["f1"]:
            best = {"f1": vm["f1"], "epoch": epoch, "threshold": thr, "val": vm}
            bad_epochs = 0
            model.save_pretrained(out_dir, safe_serialization=True)
            tokenizer.save_pretrained(out_dir)
            print(f"  -> new best checkpoint saved to {out_dir}")
        else:
            bad_epochs += 1
            if bad_epochs >= args.patience:
                print("Early stopping: validation F1 stopped improving.")
                break

    # ---- final test evaluation with the best checkpoint
    model = AutoModelForSequenceClassification.from_pretrained(out_dir).to(device)
    test_probs = predict(test_dl)
    tm = metrics(test_probs, te_y, best["threshold"])
    total_min = round((time.time() - started) / 60, 1)
    print(f"\nTEST (threshold {best['threshold']:.2f} tuned on validation): F1={tm['f1']:.4f} "
          f"P={tm['precision']:.4f} R={tm['recall']:.4f} AUC={tm.get('roc_auc', 0):.4f} | total {total_min} min")

    meta = {
        "model_name": args.model,
        "num_labels": 2,
        "max_length": args.max_length,
        "threshold": best["threshold"],
        "best_epoch": best["epoch"],
        "best_val_f1": best["f1"],
        "val_metrics": best.get("val"),
        "test_metrics": tm,
        "epochs_trained": len(history),
        "quick_test": bool(args.quick_test),
        "device": gpu_name or "cpu",
        "mixed_precision": str(amp_dtype).replace("torch.", "") if use_amp else "fp32",
        "batch_size": args.batch_size,
        "grad_accum": args.grad_accum,
        "learning_rate": args.lr,
        "training_minutes": total_min,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "train_samples": len(tr_x),
    }
    (out_dir / "train_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (out_dir / "training_history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")

    tf = CKPT_ROOT / "tfidf_fallback" / "evaluation_results.json"
    if tf.exists():
        tf_f1 = json.loads(tf.read_text())["test_metrics"]["f1"]
        winner = "CodeBERT" if (tm["f1"] > tf_f1 and not args.quick_test) else "TF-IDF"
        print(f"TF-IDF test F1 = {tf_f1:.4f} -> the backend will use {winner} (RP_MODEL=auto).")


if __name__ == "__main__":
    main()
