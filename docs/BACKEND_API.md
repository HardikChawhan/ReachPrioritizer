# Backend & REST API (`backend/`)

FastAPI service (Python 3.10+). Start it with:

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

Interactive OpenAPI docs: **http://127.0.0.1:8000/docs**.

## Modules

| Module | Responsibility |
|---|---|
| `app/main.py` | App factory, CORS, router registration, start-up (database init, marking interrupted scans as failed), `/health` |
| `app/config.py` | All settings, overridable through environment variables (table below) |
| `app/models/database.py` | SQLite schema v2, connection factory (WAL, foreign keys), migration from the v1 prototype schema |
| `app/schemas/models.py` | Pydantic request/response models (`ProjectOut`, `ScanOut`, `FindingOut`, `FindingDetailOut`, `PathStep`) |
| `app/core/upload_handler.py` | `inspect_zip`, `extract_project_zip`, `single_root`: archive safety checks and extraction |
| `app/core/orchestrator.py` | The scan pipeline (`run_scan`), `build_findings` (also used by the evaluation), `summarize`, `graph_nodes` |
| `app/services/analyzer_runner.py` | Runs `node analyzer/analyze.js` as a subprocess with a timeout and turns failures into readable errors |
| `app/services/ai_inference.py` | Bridge to `ai/inference/predictor.py`: function scoring and model selection info |
| `app/services/risk_scorer.py` | The risk formula, categories and score breakdown |
| `app/services/semgrep_scanner.py` | Optional Semgrep run with path, severity and CWE normalization |
| `app/services/persistence.py` | All SQL: projects, scans, atomic result saving, findings queries with sorting, graph, stats |
| `app/services/exporters.py` | JSON, SARIF 2.1.0 and CSV exports |
| `app/api/routes_*.py` | HTTP endpoints, grouped by resource |

## Scan pipeline (`core/orchestrator.py`)

| Stage (shown in the UI) | Progress | Work |
|---|---|---|
| Queued | 0 | Waiting for a worker slot (`RP_MAX_CONCURRENT_SCANS`) |
| Unpacking project | 5 | Safe extraction into a temporary directory; a single top-level folder is unwrapped |
| Parsing code, building call graph, tracking taint | 20 | `run_analyzer()` |
| Scoring functions with the AI model | 55 | `score_functions()`; AI failures never fail the scan |
| Running Semgrep rules | 70 | Only if `RP_ENABLE_SEMGREP=1` and `semgrep` is installed |
| Prioritizing findings | 82 | `build_findings()` |
| Saving results | 92 | One transaction: nodes, edges, entry points, findings |
| Completed / Failed | 100 | Summary JSON stored on the scan |

`build_findings` creates one finding per analyzer finding (detector `reachprioritizer-taint`), adds Semgrep findings that don't duplicate an existing `(function, CWE)`, and adds **AI-only** findings for functions with probability ≥ max(model threshold, `RP_AI_ONLY_MIN_PROB`) that have no other finding. Each finding gets a risk score, a category and a breakdown (see `risk_scorer.py`).

## Risk score

```
base = 0.45·severity + 0.35·exploitability + 0.20·ai_probability
risk = 100 · base · reachability_multiplier
```

| Input | Values |
|---|---|
| severity | critical 1.0 · high 0.8 · medium 0.55 · low 0.3 · info 0.1 |
| exploitability (taint) | user_input 1.0 · parameter 0.6 · none 0.35 · unknown (AI-only) 0.3 |
| reachability multiplier | reachable 1.0 · unknown 0.6 · startup_only 0.4 · unreachable 0.2 |
| category | Critical ≥ 70 · High ≥ 45 · Medium ≥ 25 · Low < 25 |

`risk_breakdown` stores each weight, each contribution in points, and the multiplier.

## Endpoints

### Health
| Method | Path | Response |
|---|---|---|
| GET | `/health`, `/api/health`, `/` | `{status: healthy\|degraded, version, node, analyzer}` (degraded = Node.js or the analyzer is missing) |

### Projects
| Method | Path | Notes |
|---|---|---|
| POST | `/api/projects/upload` | `multipart/form-data`: `file` (.zip), `name` (optional), `auto_scan` (default `true`). Returns `{project, scan}`. Errors: 400 (not a zip / unsafe / no sources), 413 (too large) |
| GET | `/api/projects` | List with `scan_count`, `last_scan_at` |
| GET | `/api/projects/{project_id}` | One project |
| DELETE | `/api/projects/{project_id}` | Deletes the project, its scans (cascade) and the uploaded archive |

### Scans
| Method | Path | Notes |
|---|---|---|
| POST | `/api/scans` | Body `{project_id, entry_points?: ["src/x.js", "src/y.js:fn"]}` → 202 with the queued scan |
| GET | `/api/scans?project_id=&limit=` | Newest first |
| GET | `/api/scans/{scan_id}` | `status` (queued/running/completed/failed), `stage`, `progress`, `summary`, `error_message`, `model_used`, `analysis_mode`, `duration_ms` |
| DELETE | `/api/scans/{scan_id}` | 409 while running |
| GET | `/api/scans/{scan_id}/entry-points` | `[{node_id, kind, label, active, file_path, line}]` |
| GET | `/api/scans/{scan_id}/export?format=json\|sarif\|csv` | File download; 409 if the scan has not completed |

**Scan summary fields:** `files_analyzed, functions, edges, parse_errors, functions_by_reachability, entry_points{routes, inactive_routes, startup, other}, analysis_mode, findings_total, actionable, deprioritized, noise_reduction_pct, by_risk_category, by_reachability, by_severity, by_taint, top_cwes, max_risk, model{…}, duration_ms, analyzer_ms`.

### Findings
| Method | Path | Notes |
|---|---|---|
| GET | `/api/scans/{scan_id}/findings` | Filters (comma lists allowed): `severity`, `reachability`, `category`, `taint`, `finding_type` (`static_finding`/`ai_prediction`), `q` (search in file, function, CWE, title, message), `sort` = `risk` (default), `severity`, `ai`, `file` |
| GET | `/api/scans/{scan_id}/findings/{finding_id}` | Everything above plus `source_code`, `call_path_steps[]` and `taint_path_steps[]` (resolved to `{id, name, file_path, line, node_type}`) |

**Finding fields:** `finding_id, scan_id, function_id, function_name, file_path, start_line, end_line, line, related_lines, snippet, prediction, vulnerability_probability, model_used, rule_id, title, rule_message, severity, cwe, category, sink, taint, reachability_status, entry_point, call_path, taint_path, risk_score, risk_category, risk_breakdown, finding_type, detector, created_at`.

### Call graph
| Method | Path | Notes |
|---|---|---|
| GET | `/api/scans/{scan_id}/graph?focus=all\|reachable\|findings&include_modules=true` | `nodes` (`node_id, name, file_path, line, end_line, node_type, reachability, entry_kind, ai_probability, finding_count, max_risk`), `edges` (`caller_id, callee_id, kind, line`), `entry_points`. `focus=findings` keeps only the functions on attack paths and taint paths. |

### Model, evaluation, stats
| Method | Path | Notes |
|---|---|---|
| GET | `/api/model/status` | `active_model` (name, threshold, selection reason, test metrics), `checkpoints` (eligibility and notes), `load_errors`, `dataset` (from `reports/dataset_statistics.json`) |
| GET | `/api/evaluation` | Contents of `evaluation/results/comparative_evaluation.json` (404 until the experiments have been run) |
| GET | `/api/stats` | Totals plus risk, reachability and CWE distributions over each project's latest completed scan |

## Example session

```bash
curl -F file=@test-applications/express-app.zip -F name=demo http://127.0.0.1:8000/api/projects/upload
# -> {"project": {...}, "scan": {"scan_id": "SCAN", "status": "queued", ...}}
curl http://127.0.0.1:8000/api/scans/SCAN                                  # poll until "completed"
curl "http://127.0.0.1:8000/api/scans/SCAN/findings?reachability=reachable&taint=user_input"
curl -o report.sarif "http://127.0.0.1:8000/api/scans/SCAN/export?format=sarif"
```

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RP_DB_PATH` | `backend/reachprioritizer.db` | SQLite file |
| `RP_UPLOAD_DIR` | `<temp>/reachprioritizer_uploads` | Where uploaded archives are kept |
| `RP_MODEL` | `auto` | `auto` (best measured test F1), `tfidf`, `codebert` |
| `RP_CHECKPOINT_DIR` | `ai/checkpoints` | Model directory |
| `NODE_EXE` | `node` on PATH | Node.js executable |
| `RP_ANALYZER_TIMEOUT` | `600` | Seconds before the analyzer is stopped |
| `RP_MAX_ZIP_MB` | `100` | Upload size limit |
| `RP_MAX_UNCOMPRESSED_MB` | `500` | Total extracted size limit |
| `RP_MAX_FILE_MB` | `20` | Per-file extraction limit |
| `RP_MAX_FILES_IN_ZIP` | `20000` | Archive entry limit |
| `RP_MAX_COMPRESSION_RATIO` | `200` | Zip-bomb detection threshold |
| `RP_MAX_CONCURRENT_SCANS` | `2` | Worker slots |
| `RP_AI_ONLY_MIN_PROB` | `0.85` | Minimum probability for AI-only findings |
| `RP_ENABLE_SEMGREP` | `0` | `1` to add Semgrep findings |
| `RP_SEMGREP_CONFIG` | `p/javascript` | Semgrep ruleset |
| `RP_CORS_ORIGINS` | localhost:5173, 4173, 3000 | Allowed browser origins (comma-separated) |

## Tests

```bash
cd backend
python -m pytest
```

| File | Covers |
|---|---|
| `tests/test_api.py` | Full pipeline through the API on the test apps: prioritization order, secure app with zero rule findings, graph focus, SARIF/CSV export, filters, rescan keeps older graphs, delete, model status, stats |
| `tests/test_upload.py` | Path traversal, absolute and drive-letter paths, symlinks, zip bombs, corrupt archives, archives without sources, single-root unwrapping |
| `tests/test_risk_scorer.py` | Formula values, ordering properties, breakdown consistency, category thresholds |
| `tests/conftest.py` | Isolated temp database and upload directory, TF-IDF model forced |
