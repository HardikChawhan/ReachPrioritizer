# AI Model & Training (`ai/`)

ReachPrioritizer uses a **function-level vulnerability classifier**: given a function's source code, it returns the probability that the function is vulnerable. It is **one signal** in the risk score (20% weight). Concrete findings come from the taint engine. Functions with a very high probability (≥ 0.85) and no rule match are shown as "AI-only" suggestions.

## Files

| Path | Purpose |
|---|---|
| `ai/inference/predictor.py` | `TfidfPredictor`, `CodeBertPredictor`, `describe_checkpoints()`, `get_predictor()` (model selection and caching), `normalize_source()` (identical to the dataset normalization) |
| `ai/training/train_fallback.py` | Trains TF-IDF + Logistic Regression (CPU, about a minute) |
| `ai/training/train_codebert.py` | Fine-tunes CodeBERT or another RoBERTa-style code model on a GPU |
| `ai/training/check_gpu.py` | Verifies that PyTorch can use your NVIDIA GPU |
| `ai/requirements-gpu.txt` | Extra packages for CodeBERT (install PyTorch first) |
| `ai/checkpoints/tfidf_fallback/` | Shipped model: `vectorizer.joblib`, `classifier.joblib`, `metadata.json`, `evaluation_results.json` |
| `ai/checkpoints/codebert_vuln_classifier/` | Created by CodeBERT training (git-ignored, ~500 MB) |

## Models

| | TF-IDF + Logistic Regression | CodeBERT (fine-tuned) |
|---|---|---|
| Input | Word 1–2-grams of the normalized source (10,000 features, sublinear TF) | Up to 512 BPE tokens |
| Classifier | Logistic regression, `class_weight=balanced` | `microsoft/codebert-base` + classification head, class-weighted cross-entropy |
| Hardware | Any CPU | NVIDIA GPU recommended |
| Test F1 / precision / recall / ROC-AUC | **0.402 / 0.276 / 0.737 / 0.806** | Measured when you train it |
| Status | Active (shipped) | Selected automatically if its test F1 is higher |

The low precision is typical of function-level classification with a 9:1 class imbalance. This is why the model is a weighted signal and not the detector.

## Model selection (`RP_MODEL`)

- `auto` (default): from the eligible checkpoints, use the one with the highest **recorded test F1**. A CodeBERT checkpoint is eligible only if its weights exist, it was **not** a `--quick-test` run, and it has test metrics in `train_meta.json`. This prevents the v1 failure, where a smoke-test checkpoint with validation F1 = 0.0 silently replaced the working model.
- `tfidf` / `codebert`: force a model. If CodeBERT fails to load, the backend falls back to TF-IDF.

The **Model & Research** page and `GET /api/model/status` show the active model, why it was chosen, and every checkpoint's eligibility.

## Training the TF-IDF model

```bash
bash scripts/fetch_dataset.sh          # once: builds data/processed/splits/
python ai/training/train_fallback.py
```

It writes the four checkpoint files and prints validation and test metrics. The decision threshold is 0.5.

## Training CodeBERT on a laptop GPU (RTX 4060 / RTX 5070 Ti)

Estimated time for the full split (17,621 functions, up to 4 epochs with early stopping, bf16 mixed precision, dynamic padding):

| GPU | VRAM | Estimated time |
|---|---|---|
| RTX 4060 Laptop | 8 GB | ~45–90 min |
| RTX 5070 Ti Laptop | 12 GB | ~25–45 min |
| CPU only | – | many hours (not recommended) |

The CPU model (e.g. Ryzen 7 vs Ryzen 9) barely matters. Keep the laptop plugged in and on its performance power profile, because laptop GPUs throttle on battery and when hot.

**1. Check the NVIDIA driver:** run `nvidia-smi`. RTX 50-series (Blackwell) needs a driver that reports CUDA **12.8+**.

**2. Install the CUDA build of PyTorch** (a separate venv with Python 3.10–3.12 is recommended):

```bash
python -m venv .venv-gpu
# Windows: .venv-gpu\Scripts\activate     Linux/macOS: source .venv-gpu/bin/activate
pip install --upgrade pip
pip install torch --index-url https://download.pytorch.org/whl/cu128
pip install -r ai/requirements-gpu.txt
```

The `cu128` build supports both the RTX 4060 and the RTX 5070 Ti. If you installed `torch` without `--index-url`, you have the CPU-only build: reinstall with the command above.

**3. Verify:** `python ai/training/check_gpu.py`

**4. Train:**

```bash
python ai/training/train_codebert.py --quick-test   # optional 2-minute pipeline check (never used by the app)
python ai/training/train_codebert.py                # full training
```

| Option | Default | Notes |
|---|---|---|
| `--model` | `microsoft/codebert-base` | e.g. `microsoft/unixcoder-base` |
| `--epochs` | 4 | Early stopping on validation F1 |
| `--batch-size` / `--grad-accum` | 16 / 2 | Out of memory? Use `--batch-size 8 --grad-accum 4` |
| `--lr` | 2e-5 | AdamW with linear warm-up (6%) and decay |
| `--max-length` | 512 | Tokens per function |
| `--patience` | 2 | Early-stopping patience in epochs |
| `--no-amp` | off | Disable mixed precision |

**What the script does:** loads and normalizes the splits, tokenizes once, trains with bf16 (or fp16 with gradient scaling), evaluates on validation every epoch, **tunes the decision threshold on validation**, saves the best checkpoint, evaluates once on the test split with that threshold, and writes `train_meta.json` (test metrics, threshold, device, timing) and `training_history.json`. At the end it prints which model the backend will use. Restart the backend to load the new model.

## Inference details
- Sources are normalized exactly like the training data.
- CodeBERT runs in batches of 16 on the GPU if one is available, otherwise on the CPU. It truncates to `max_length` tokens.
- Predictors are cached per process. AI errors never fail a scan: the scan continues without AI scores.
