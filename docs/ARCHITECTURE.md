# Architecture

ReachPrioritizer is made of four cooperating parts:

| Part | Language | Folder | Responsibility |
|---|---|---|---|
| Analysis engine | Node.js | `analyzer/` | Parse code; build the call graph; detect entry points; compute reachability and call paths; taint-track user input into sinks |
| Backend API | Python / FastAPI | `backend/` | Uploads, scan orchestration, AI scoring, risk scoring, persistence, reports |
| AI | Python | `ai/` | Function-level vulnerability classifier (TF-IDF or CodeBERT) plus training scripts |
| Frontend | React / Vite | `frontend/` | Dashboard, results, attack paths, call graph, guided tour, Learn pages |

## System diagram

```mermaid
flowchart TB
  subgraph Browser
    UI[React SPA<br/>Overview · Scan results · Finding detail · Call graph · Research · Learn · Tour]
  end
  subgraph Backend[FastAPI backend - backend/app]
    R[REST routes<br/>api/routes_*.py]
    O[Orchestrator<br/>core/orchestrator.py]
    U[Safe ZIP handling<br/>core/upload_handler.py]
    AR[Analyzer runner<br/>services/analyzer_runner.py]
    AI[AI inference<br/>services/ai_inference.py]
    RS[Risk scorer<br/>services/risk_scorer.py]
    P[Persistence<br/>services/persistence.py]
    X[Exporters<br/>JSON · SARIF · CSV]
    SG[Semgrep - optional]
  end
  subgraph Engine[Analysis engine - analyzer/]
    A[analyze.js CLI] --> PR[lib/project.js]
    PR --> FA[lib/file_analyzer.js]
    FA --> RU[lib/rules.js]
    FA --> AST[lib/ast.js + @babel/parser]
  end
  subgraph Model[ai/]
    PRED[inference/predictor.py] --> CK[(checkpoints/)]
  end
  DB[(SQLite<br/>reachprioritizer.db)]

  UI -- /api/* via Vite proxy --> R
  R --> O
  R --> P
  R --> X
  O --> U
  O --> AR -- subprocess, JSON --> A
  O --> AI --> PRED
  O --> SG
  O --> RS
  O --> P --> DB
```

## Scan lifecycle

```mermaid
sequenceDiagram
  participant B as Browser
  participant API as FastAPI
  participant W as Worker thread
  participant N as analyze.js (Node)
  participant M as AI model
  participant DB as SQLite
  B->>API: POST /api/projects/upload (zip) or /from-github (url)
  API->>API: stream to disk (or download from codeload.github.com), inspect_zip() (size, traversal, zip-bomb)
  API->>DB: insert project + scan (status=queued)
  API-->>B: {project, scan}
  API->>W: background task run_scan()
  W->>DB: status=running, stage="Unpacking project"
  W->>W: extract_project_zip() -> temp dir
  W->>N: node analyzer/analyze.js --project dir --with-source
  N-->>W: nodes, edges, entry_points, findings, reachability
  W->>M: predict_proba(function sources)
  M-->>W: probability per function
  W->>W: build_findings(): attach AI, reachability, risk score, attack simulation
  W->>W: dependency_check(): package.json -> OSV advisories -> call-graph usage
  W->>DB: save nodes, edges, entry points, findings (one transaction)
  W->>DB: status=completed + summary
  loop every second
    B->>API: GET /api/scans/{id}
  end
  B->>API: GET /api/scans/{id}/findings, /graph, /findings/{fid}
```

## Design decisions

| Decision | Why |
|---|---|
| **One parser (Babel) for everything** | v1 used tree-sitter in Python for functions and Babel in Node for the call graph, and joined the two by name. They named functions differently, so results were sometimes attributed to the wrong function. Now one engine emits functions, edges, reachability and findings with a single ID scheme: `path/to/file.js::functionName`. |
| **Engine as a subprocess with JSON I/O** | Keeps the JS analysis in JS (best parser ecosystem) and the ML in Python. The engine is also a standalone CLI. |
| **Static only, never execute uploads** | Safety: uploaded code is untrusted. |
| **Two-level entry points (startup vs request)** | Distinguishes "runs when the server boots" from "runs when an attacker sends a request". This is what makes `startup_only` possible. |
| **Taint summaries per parameter** | Cheap interprocedural analysis: each function records which parameters reach sinks. Call sites are linked by a BFS, so no whole-program fixpoint is needed. |
| **AI as a weighted signal (20%)** | The function-level classifier has low precision (0.28 on the test split). Concrete findings come from rules with data flow. |
| **Model auto-selection by measured test F1** | Prevents shipping an untrained or smoke-test checkpoint by mistake (a v1 bug). |
| **SQLite + worker threads** | Zero-install, adequate for a research tool. Scans run in a bounded thread pool (`RP_MAX_CONCURRENT_SCANS`) so the API stays responsive. |
| **Per-scan composite keys for graph nodes** | v1 used a global primary key, so rescanning a project overwrote older scans' graphs. |

## Data model (SQLite, schema v3)

```mermaid
erDiagram
  projects ||--o{ scans : has
  scans ||--o{ findings : produces
  scans ||--o{ call_graph_nodes : contains
  scans ||--o{ call_graph_edges : contains
  scans ||--o{ entry_points : detects
  projects { text project_id PK
             text name
             text upload_path
             int file_count
             int size_bytes
             text source_type
             text source_url
             text source_ref }
  scans { text scan_id PK
          text project_id FK
          text status
          text stage
          int progress
          text summary_json
          text model_used
          text analysis_mode
          text source_ref }
  findings { text finding_id PK
             text scan_id FK
             text function_id
             text cwe
             text severity
             text taint
             text reachability_status
             text call_path
             text taint_path
             real risk_score
             text risk_breakdown
             text extra_json }
  call_graph_nodes { text scan_id PK
                     text node_id PK
                     text reachability
                     text entry_kind
                     real ai_probability
                     real max_risk }
  call_graph_edges { int edge_id PK
                     text caller_id
                     text callee_id
                     text kind }
  entry_points { text node_id
                 text kind
                 text label
                 int active }
```

All child tables use `ON DELETE CASCADE`. JSON-valued columns (`call_path`, `taint_path`, `risk_breakdown`, `summary_json`, …) are stored as text. `findings.extra_json` holds the attack simulation and the dependency details. A v1 database is detected at start-up and recreated; a v2 database is upgraded in place by adding the new columns, so existing scans survive (`models/database.py`).

## Security of the tool itself

- Uploads are streamed with a size cap (`RP_MAX_ZIP_MB`, default 100 MB).
- `inspect_zip` rejects absolute paths, `..` components, drive letters, too many entries, archives that expand beyond `RP_MAX_UNCOMPRESSED_MB`, suspicious compression ratios, and archives without source files.
- Extraction skips symlinks, non-source files and `node_modules`, re-checks that each destination stays inside the extraction directory, and enforces per-file and total byte limits while streaming.
- The engine only parses files and never executes them. Each scan works in a temporary directory that is deleted afterwards.
- CORS is restricted to configured origins (`RP_CORS_ORIGINS`). There is **no authentication**: run it locally or behind your own auth proxy.

## Related documents

- [ANALYSIS_ENGINE.md](ANALYSIS_ENGINE.md) — algorithms in detail
- [BACKEND_API.md](BACKEND_API.md) — every endpoint and module
- [FRONTEND.md](FRONTEND.md) — pages, components, tour
- [AI_MODEL_AND_TRAINING.md](AI_MODEL_AND_TRAINING.md)
