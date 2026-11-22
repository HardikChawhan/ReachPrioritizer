# Repository Guide — every file explained

```
ReachPrioritizer/
├── analyzer/            Node.js static-analysis engine
├── backend/             FastAPI service
├── ai/                  ML inference + training
├── frontend/            React web app
├── test-applications/   Labeled benchmark apps (+ demo zips)
├── evaluation/          Experiments, baselines, real-world ground truth, results
├── preprocessing/       Phase 1 dataset pipeline
├── reports/             Phase 1 dataset statistics (JSON)
├── data/                Dataset location (only split_manifest.json is versioned)
├── scripts/             Helper scripts
├── docs/                Documentation, research paper, screenshots
├── package.json         Root Node deps (@babel/parser, minimist) + scripts
└── README.md
```

## Root

| File | Purpose |
|---|---|
| `README.md` | Project overview, quick start, results, links |
| `setup.bat` | Windows one-time setup: checks Node/Python, creates `.venv`, installs every dependency, self-check |
| `start.bat` | Windows launcher: starts the API and the website, waits until they are ready, opens the browser |
| `stop.bat` | Windows: stops the API and the website |
| `LICENSE` | MIT license |
| `package.json` / `package-lock.json` | Node dependencies of the engine and preprocessing; scripts: `analyze`, `test:analyzer`, `phase1`, and the individual Phase 1 steps |
| `.gitignore` | Excludes dependencies, the database, uploads, large dataset files, CodeBERT weights, generated Markdown reports, benchmark checkouts |
| `.gitattributes` | Normalizes line endings to LF; marks binaries |

## `analyzer/` — static analysis engine

| File | Purpose |
|---|---|
| `analyze.js` | CLI entry: `node analyzer/analyze.js --project <dir>` |
| `lib/ast.js` | Babel parser setup (JS/JSX/TS/TSX) and AST helpers |
| `lib/rules.js` | Sources, sanitizers, sinks (`matchCallSink`) and patterns for SQL, HTML, ReDoS and secrets |
| `lib/file_analyzer.js` | Per-file analysis: functions, bindings, exports, call records, routes, server indicators, intra-procedural taint, rule checks |
| `lib/project.js` | Cross-file resolution, call edges, entry points, reachability, interprocedural taint, finding merge, JSON output |
| `test/engine.test.js` | 11 tests: 4 ground-truth apps plus focused cases (tagged SQL, promisify, guard clauses, axios config, TypeScript, secrets) |
| `test/groundtruth.js` | Helpers that map ground-truth entries to analyzer nodes |
| `package.json` | Engine metadata, `npm test` |

Details: [ANALYSIS_ENGINE.md](ANALYSIS_ENGINE.md)

## `backend/` — API service

| File | Purpose |
|---|---|
| `requirements.txt` | Python dependencies (FastAPI, uvicorn, scikit-learn, joblib, numpy, pytest, httpx) |
| `pytest.ini` | Test configuration |
| `app/main.py` | FastAPI app, CORS, routers, start-up hooks, `/health` |
| `app/config.py` | Environment-driven settings |
| `app/models/database.py` | SQLite schema v2 and migration |
| `app/schemas/models.py` | Pydantic models |
| `app/core/orchestrator.py` | Scan pipeline, `build_findings`, scan summary, graph node enrichment |
| `app/core/upload_handler.py` | ZIP safety checks and extraction |
| `app/services/analyzer_runner.py` | Runs the Node engine |
| `app/services/ai_inference.py` | Function scoring through `ai/inference/predictor.py` |
| `app/services/risk_scorer.py` | Risk formula and breakdown |
| `app/services/persistence.py` | All database reads and writes |
| `app/services/exporters.py` | JSON / SARIF / CSV reports |
| `app/services/semgrep_scanner.py` | Optional Semgrep integration |
| `app/api/routes_projects.py` | Upload, list, get, delete projects |
| `app/api/routes_scans.py` | Start, list, get, delete scans; entry points; export |
| `app/api/routes_findings.py` | Finding list (filters, search, sort) and detail (resolved paths) |
| `app/api/routes_graph.py` | Call graph with focus modes |
| `app/api/routes_model.py` | Model status and dataset summary |
| `app/api/routes_evaluation.py` | Serves the evaluation results JSON |
| `app/api/routes_stats.py` | Dashboard statistics |
| `tests/test_api.py` | End-to-end API and pipeline tests on the test apps |
| `tests/test_upload.py` | Archive safety tests |
| `tests/test_risk_scorer.py` | Scoring tests |
| `tests/conftest.py` | Isolated test database and uploads |
| `reachprioritizer.db` | *(created at runtime, git-ignored)* |

Details: [BACKEND_API.md](BACKEND_API.md)

## `ai/` — machine learning

| File | Purpose |
|---|---|
| `inference/predictor.py` | Model loading, selection by measured test F1, batched prediction, source normalization |
| `training/train_fallback.py` | Trains TF-IDF + Logistic Regression |
| `training/train_codebert.py` | GPU fine-tuning of CodeBERT (mixed precision, early stopping, threshold tuning) |
| `training/check_gpu.py` | GPU sanity check |
| `requirements-gpu.txt` | Transformers & co. (install PyTorch CUDA first) |
| `checkpoints/tfidf_fallback/*` | The shipped model and its metrics |
| `checkpoints/codebert_vuln_classifier/` | *(created by training, git-ignored)* |

Details: [AI_MODEL_AND_TRAINING.md](AI_MODEL_AND_TRAINING.md)

## `frontend/` — web app

| File | Purpose |
|---|---|
| `index.html`, `public/favicon.svg` | HTML shell and icon |
| `vite.config.js` | Dev and preview servers with the `/api` proxy, chunk splitting |
| `tailwind.config.js`, `postcss.config.js`, `src/styles/globals.css` | Design tokens and component classes |
| `src/main.jsx`, `src/App.jsx` | Bootstrap, fonts, router, error boundary, tour provider |
| `src/pages/*.jsx` | Dashboard, NewScan, Scans, ScanResults, FindingDetail, CallGraph, Research, Learn |
| `src/components/*.jsx` | Layout, UI primitives, AttackPath, CodeView, ParticleField |
| `src/tour/Tour.jsx`, `src/tour/steps.js` | Guided tour engine and script |
| `src/lib/api.js`, `src/lib/format.js` | API client and presentation helpers |

Details: [FRONTEND.md](FRONTEND.md)

## `test-applications/` — benchmark apps

| Path | Purpose |
|---|---|
| `vulnerable-app/` | 8 vulnerabilities (SQLi, path traversal, command injection, eval, XSS, prototype pollution) |
| `secure-app/` | The same features implemented securely: must produce zero findings |
| `mixed-app/` | Reachable and dead modules: demonstrates prioritization |
| `express-app/` | Realistic Express app: mounted routers, class service, dead router, unused controller, sanitizers, start-up job, hardcoded secret |
| `*/ground-truth.json` | Labels (schema v2) |
| `*.zip` | Ready-to-upload demo archives (without the ground truth) |

## `evaluation/`

| Path | Purpose |
|---|---|
| `scripts/run_experiments.py` | Runs all experiments and writes the results |
| `baselines/legacy_regex_scanner.py` | The v1 regex rule engine, kept as a baseline |
| `baselines/eslint_security.py`, `baselines/eslint/package.json` | ESLint + eslint-plugin-security baseline (`npm install` in that folder) |
| `realworld/fetch_realworld.sh` | Clones NodeGoat and DVNA at pinned commits into `realworld/repos/` (git-ignored) |
| `realworld/*.ground-truth.json` | Documented vulnerabilities of the real-world apps |
| `results/comparative_evaluation.json`, `results/RESULTS.md` | Latest results (generated) |

Details: [EVALUATION.md](EVALUATION.md)

## `preprocessing/` — Phase 1 dataset pipeline

| File | Purpose |
|---|---|
| `run_phase1.js` | Runs all steps (`npm run phase1`) |
| `inspect_schema.js` | Documents the JsVul schema |
| `inventory.js` | Dataset inventory |
| `normalize.js` | Extraction and source normalization |
| `validate_js.js` | Babel parse validation |
| `deduplicate.js` | Filtering and duplicate detection |
| `leakage_check.js` | Near-duplicate / pair analysis |
| `split.js` | Repository-disjoint seeded split |
| `statistics.js` | Dataset statistics |

Details: [DATASET.md](DATASET.md)

## `reports/`, `data/`, `scripts/`, `docs/`

| Path | Purpose |
|---|---|
| `reports/dataset_statistics.json` | Read by the Model & Research page |
| `reports/dataset_inventory.json`, `duplicate_report.json`, `javascript_validation_report.json` | Phase 1 evidence |
| `data/processed/split_manifest.json` | Which repository went to which split (reproducibility) |
| `data/raw/`, `data/processed/*.jsonl`, `data/processed/splits/` | *(rebuilt by `scripts/fetch_dataset.sh`, git-ignored)* |
| `scripts/fetch_dataset.sh` | Downloads JsVul (pinned) and runs Phase 1 |
| `docs/*.md` | This documentation |
| `docs/RESEARCH_PAPER.md` | Full technical report / paper source |
| `docs/images/*.jpg` | Screenshots used in the docs |
