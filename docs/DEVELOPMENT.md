# Development Guide

## Requirements

| Tool | Version | Used by |
|---|---|---|
| Node.js | 18+ (tested with 22) | analysis engine, preprocessing, frontend |
| Python | 3.10–3.12 recommended (3.13 works) | backend, AI |
| Git | any | dataset and benchmark download scripts |
| NVIDIA GPU + CUDA PyTorch | optional | CodeBERT training |

## Setup

**Windows shortcut:** after cloning, double-click `setup.bat` once, then `start.bat` every time you want to run the project. `stop.bat` stops it. The rest of this section is the manual equivalent (and the only way on Linux/macOS).

```bash
git clone https://github.com/HardikChawhan/ReachPrioritizer.git
cd ReachPrioritizer
npm install                                  # engine deps
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
pip install -r backend/requirements.txt
cd frontend && npm install && cd ..
```

## Run

```bash
# terminal 1
cd backend && uvicorn app.main:app --reload --port 8000
# terminal 2
cd frontend && npm run dev        # open http://localhost:5173
```

Production-style frontend: `cd frontend && npm run build && npm run preview` (http://localhost:4173, still proxies `/api`).

## Everyday commands

| Task | Command |
|---|---|
| Analyze a folder from the CLI | `node analyzer/analyze.js --project path/to/app --pretty` |
| Engine tests | `npm run test:analyzer` |
| Backend tests | `cd backend && python -m pytest` |
| Evaluation | `python evaluation/scripts/run_experiments.py` |
| Rebuild the dataset | `bash scripts/fetch_dataset.sh` |
| Train TF-IDF | `python ai/training/train_fallback.py` |
| Train CodeBERT | `python ai/training/train_codebert.py` (see [AI_MODEL_AND_TRAINING.md](AI_MODEL_AND_TRAINING.md)) |
| Rebuild the demo zips | `cd test-applications && zip -r express-app.zip express-app -x express-app/ground-truth.json` (same for each app) |

## Configuration
All backend settings are environment variables; see the table in [BACKEND_API.md](BACKEND_API.md#configuration-environment-variables). Examples:

```bash
RP_MODEL=tfidf RP_MAX_ZIP_MB=200 uvicorn app.main:app --port 8000          # Linux/macOS
$env:RP_MODEL="tfidf"; uvicorn app.main:app --port 8000                     # Windows PowerShell
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| UI shows "API offline" / "Cannot reach the ReachPrioritizer API" | Start the backend on port 8000 (or set `VITE_API_TARGET`) |
| Scan fails with "Node.js was not found" | Install Node.js 18+ and restart the terminal, or set `NODE_EXE` |
| Scan fails with "Cannot find module '@babel/parser'" | Run `npm install` in the project root |
| `/health` says `degraded` | Node.js or `analyzer/analyze.js` is missing |
| `pip install` fails on a very new Python | Use Python 3.12 (`py -3.12 -m venv .venv` on Windows) |
| Scikit-learn `InconsistentVersionWarning` | Harmless: the shipped model was saved with scikit-learn 1.8. Retrain with `train_fallback.py` to silence it |
| CodeBERT training runs on CPU | You installed CPU-only PyTorch; reinstall with `--index-url https://download.pytorch.org/whl/cu128` and run `ai/training/check_gpu.py` |
| Old scans disappeared after upgrading | Expected: the v1 database schema is replaced automatically on first start |
| Tour does not appear on first visit | It was already dismissed; click **Tour** in the header (or clear the `reachprioritizer.tour.seen.v1` localStorage key) |

## Adding things

| You want to… | Where |
|---|---|
| Detect a new vulnerability type | `analyzer/lib/rules.js` (`matchCallSink`) or `runRules` in `file_analyzer.js`. Add a test in `analyzer/test/engine.test.js`, a CWE entry in `frontend/src/lib/format.js` (`CWE_INFO`), and re-run the evaluation |
| Support a new framework's routes | `detectRouteOrServer` (`file_analyzer.js`) or the platform conventions in `detectEntryPoints` (`project.js`) |
| Change the risk formula | `backend/app/services/risk_scorer.py`; update `tests/test_risk_scorer.py`, the Learn page calculator (`frontend/src/pages/Learn.jsx`) and the docs |
| Add an API endpoint | New `backend/app/api/routes_*.py`, register it in `main.py`, add the client call to `frontend/src/lib/api.js` |
| Add a page | `frontend/src/pages/`, a route in `App.jsx`, a nav link in `components/Layout.jsx`, and optionally tour steps in `tour/steps.js` |
| Add a benchmark app | `test-applications/<name>/` with `ground-truth.json` (schema v2), then add it to `CONTROLLED` in `run_experiments.py` and `APPS` in `analyzer/test/groundtruth.js` |

## Conventions
- The engine never executes analyzed code. Keep it that way.
- Every number in the docs must come from `run_experiments.py` or a training log.
- Function ids are `relative/path.js::name` (with `#L<line>` on collisions); keep the format stable, because the frontend and the ground truth depend on it.
- Run both test suites before committing.
