# The Analysis Engine (`analyzer/`)

The engine is a dependency-light Node.js program (only `@babel/parser` and `minimist`). It reads a project directory and writes one JSON document describing functions, calls, entry points, reachability and security findings. **It never executes the analyzed code.**

```bash
node analyzer/analyze.js --project <dir> [--output result.json] [--with-source] \
                         [--entry-points src/app.js,src/jobs.js:run] [--include-tests] [--pretty]
```

| Flag | Meaning |
|---|---|
| `--project, -p` | Directory to analyze (required) |
| `--output, -o` | Write JSON to a file (default: stdout) |
| `--with-source` | Include each function's source code (the backend needs it for the AI model) |
| `--entry-points, -e` | Extra entry points: `file.js` (its top level) or `file.js:functionName` |
| `--include-tests` | Also analyze test, tooling and doc code (skipped by default) |
| `--pretty` | Indented JSON |

## Module map

| File | Responsibility |
|---|---|
| `analyze.js` | CLI wrapper, timing, output |
| `lib/ast.js` | Babel parser configuration (JS/JSX/TS/TSX, error recovery) and AST helpers (`memberChain`, `patternNames`, `stringValue`, …) |
| `lib/rules.js` | Security knowledge base: sources, sanitizers, sink matcher (`matchCallSink`), SQL/HTML/ReDoS/secret patterns, severity ranks |
| `lib/file_analyzer.js` | Per-file analysis: functions ("frames"), module bindings, exports, call records, route registrations, server indicators, intra-procedural taint, rule evaluation |
| `lib/project.js` | Project-level analysis: file collection, module resolution, call-edge resolution, entry points, reachability, interprocedural taint, finding merge, output |
| `test/engine.test.js` | Ground-truth and focused unit tests (`npm run test:analyzer`) |

## Pipeline

```mermaid
flowchart LR
  F[collectFiles] --> A[analyzeFile x N]
  A --> E[buildEdges]
  E --> EP[detectEntryPoints]
  EP --> R[computeReachability]
  R --> T[propagateTaint]
  T --> M[mergeFindings]
  M --> O[output JSON]
```

### 1. File collection
- Extensions: `.js .mjs .cjs .jsx .ts .tsx .mts .cts`. `*.min.js` and `*.d.ts` are skipped.
- Skipped directories: `node_modules`, `.git`, `dist`, `build`, `.next`, `coverage`, `vendor`, `bower_components`, `out`, `.cache`, hidden folders.
- Non-production code is skipped unless `--include-tests`: `test/ tests/ __tests__/ spec/ cypress/ e2e/ fixtures/ docs/ examples/ benchmark/` and files such as `*.test.js`, `*.spec.ts`, `Gruntfile.js`, `webpack.config.js`, `vite.config.js`, `jest.config.js`.
- Limits: 3,000 files, 1 MB per file. Skipped files are reported in `skipped_files`.

### 2. Per-file analysis (`file_analyzer.js`)
A single recursive walk with a stack of **frames** (one per function plus a `__top_level__` frame per module):

| Collected | Details |
|---|---|
| Functions | Declarations, function/arrow expressions, object methods, class methods, class-field functions. Context-aware names: `UserService.search`, `ContributionsHandler.update` (ES5 constructor `this.x = fn`), `<GET /greet handler>`, `<exec callback>`. IDs are `file::name`, with `#L<line>` added on collision. |
| Bindings | `const x = require('m')`, destructured requires, `require('m').y`, ESM default/named/namespace imports, `util.promisify(cp.exec)` aliases. Used to canonicalize callee names (`cp.exec` → `child_process.exec`). |
| Exports | `module.exports = {…} / fn / new C() / C`, `module.exports.x =`, `exports.x =`, ESM named/default exports, re-exports, `export *`. |
| Classes | Methods per class (including superclass chain); `varClass` for `x = new C()` and `this.x = new C()`. |
| Object methods | Methods of object literals assigned to variables (`const app = { get() {…} }`). |
| Call records | Callee chain, argument taint, inline callbacks, callback references, IIFEs, `require('./x')(…)`. |
| Routes | `X.get/post/put/delete/patch/all/head/options/use(path, …handlers)`, `route({ handler })`, `server.on('request', fn)`. HTTP clients (`axios.get('/x')`) are excluded. |
| Server indicators | `.listen()`, `http(s)/http2.createServer`, `require.main === module`. |

### 3. Call-graph edges (`project.js → buildEdges`)
| Edge kind | Created for |
|---|---|
| `call` | Resolved calls: local functions, imported functions (CJS/ESM, re-exports), `this.m()` (class, object literal, ES5 constructor), `obj.m()` for class instances and object literals, static class methods, `require('./x')(…)` → default export, IIFEs |
| `callback` | Function arguments, inline or by reference (`arr.map(fn)`, `router.get('/', ctrl.handle)`) |
| `import` | Module A loads module B → `A::__top_level__ → B::__top_level__` (loading a module executes it) |

Module resolution tries the exact path, the known extensions and `index.*`, and maps TypeScript ESM imports (`./x.js` → `x.ts`). Unresolved callee names are counted in `unresolved_calls` for diagnostics.

### 4. Entry points (`detectEntryPoints`)
- **Startup roots:** `package.json` `main`, `bin`, and `scripts.start/dev/serve` (`node|nodemon|ts-node|tsx|bun <file>`), searched up to 3 directories deep; files with `listen()`, `createServer`, `require.main === module`; user overrides. If none are found, modules that no other project file imports become roots.
- **Request roots:** route handlers, server request callbacks, serverless `handler` exports, and Next.js `pages/api/*` and `app/**/route.*` exports. If none exist (a library), the exported functions of the root modules form the attack surface (mode `library`).
- A request root is **active** only if the function that registers it is reachable from a startup root. Platform roots (serverless, Next.js) have no registrar and are always active.

### 5. Reachability (`computeReachability`)
Two multi-source BFS passes over all edges:
1. From startup roots → `startupParent`.
2. From active request roots → `requestParent`.

| Status | Rule |
|---|---|
| `reachable` | Reached from an active request root. In `module` mode (no request roots at all), reached from a startup root. |
| `startup_only` | Reached from a startup root but not from any request root |
| `unreachable` | Not reached |

**Call path** for a reachable function = startup path to the route's registrar + the request path from the handler to the function (duplicates removed). The engine keeps one shortest path per function.

### 6. Taint analysis

**Labels:** `U` (user input) or `P|<functionId>|<index>` (value of a parameter). Nested functions start from a copy of their parent's labels (closures).

**Propagation** (flow-insensitive fixpoint, at most 8 passes per function) through variable declarations (with destructuring), assignments (`=`, `+=`, writes to object members taint the root object), `for…in`/`for…of`, and the expression evaluator `taintOf`:

| Expression | Result |
|---|---|
| Identifier | Its label set, unless sanitized by a guard |
| Member `a.b.c` | `U` if it is a source chain; otherwise the object's taint (`.length`, `.size` are neutral) |
| Call | `U` for `req.get()/header()/param()/cookie()`; ∅ for sanitizers and boolean checks (`includes`, `test`, `startsWith`, …); otherwise object taint ∪ argument taints |
| `a + b`, template literals, `a \|\| b`, `c ? a : b`, arrays, objects, spread, `await` | Union of parts |
| Comparisons, arithmetic, `typeof`, `!`, literals, tagged templates | ∅ |

**Sources:** `req|request|ctx|context.{body,query,params,headers,cookies,signedCookies,url,originalUrl,path,files,file,hostname,rawBody,search,querystring}`, `ctx.request.*`, Lambda `event.{body,queryStringParameters,pathParameters,headers}`, `process.argv`, `location.*`, `document.cookie/URL/referrer`.

**Sanitizers:** names starting with `escape`, `sanitize`, `encode`, `purify`, `xss`, `stripTags`, `shellescape`/`shellQuote`/`quote`, `parseInt`, `parseFloat`, `Number`, `Boolean`, `basename`, `isValid`, `validate`, `toInteger`/`toNumber`…; `path.basename`, `Math.floor/round/abs`; `JSON.stringify` for XSS only.

**Guards:** an `if` whose branch exits (`return`, `throw`, `continue`, `break`, `process.exit`) sanitizes variables validated in its test, for any later sink: `ALLOWED.includes(x)`, `set.has(x)`, `/re/.test(x)`, `x.startsWith(base)`, `isSafe(x)` / `valid…(x)` / `check…(x)`, and `x !== 'literal'`. A sink *inside* an `if` that validates the variable (`if (ALLOWED.includes(x)) exec(x)`) is also safe. `typeof` checks do **not** sanitize.

**Interprocedural propagation** (`propagateTaint`):
1. Each finding whose taint comes from parameter `i` of function `f` registers a summary `f|i → finding`.
2. Each call site records the labels of its arguments. If argument `j` carries `P|g|k` (a parameter of the caller), the engine records a flow `g|k → callee|j`. If it carries `U`, the callee parameter becomes a **seed**.
3. A BFS from all seeds over the flows marks every reachable summary's findings as `user_input` and reconstructs the **taint path** (the function where input enters → … → sink function).

### 7. Rules (`rules.js` + `runRules`)

| CWE | Rule IDs | Sinks / patterns | Severity |
|---|---|---|---|
| CWE-78 | `rp.cmdi.shell-exec`, `rp.cmdi.spawn-shell`, `rp.cmdi.spawn-binary` | `child_process.exec/execSync`, `shelljs.exec`; `spawn/execFile/fork` with a tainted binary or `shell: true` | critical / high |
| CWE-94 | `rp.code.eval`, `rp.code.function-constructor`, `rp.code.vm`, `rp.code.timer-string`, `rp.code.mathjs-eval` | `eval`, `Function`, `vm.*`, string `setTimeout/setInterval`, `mathjs.eval/evaluate` | critical |
| CWE-89 | `rp.sqli.query`, `rp.sqli.string-build` | `.query/.execute/.raw/.unsafe/$queryRawUnsafe` with tainted first argument; SQL statements (SELECT…FROM, INSERT INTO, UPDATE…SET, DELETE FROM, DDL) built by concatenation/template with tainted parts. Tagged templates (`sql\`…\``) are safe. | high |
| CWE-943 | `rp.nosqli.query-object`, `rp.nosqli.where` | `find/findOne/updateOne/deleteMany/where/aggregate…` with a request object; tainted `$where` | medium / high |
| CWE-22 | `rp.path.fs`, `rp.path.send-file` | `fs`, `fs/promises`, `fs-extra`, `graceful-fs` path APIs; `res.sendFile/download/attachment` | high |
| CWE-918 | `rp.ssrf.http-client`, `rp.ssrf.fetch` | `http(s).get/request`, `axios(…)`/`axios.get…` (including `{url}` config), `got`, `request`, `node-fetch`, `undici`, `superagent`, `needle`, global `fetch` | high |
| CWE-601 | `rp.redirect.open` | `res|reply|ctx.redirect(tainted)` | medium |
| CWE-79 | `rp.xss.response`, `rp.xss.html-build`, `rp.xss.inner-html`, `rp.xss.document-write`, `rp.xss.insert-html`, `rp.xss.react-dangerous-html` | `res.send/write/end` with user input or HTML strings; HTML built from tainted parts; `innerHTML/outerHTML`; `document.write`; `insertAdjacentHTML`; `dangerouslySetInnerHTML` | medium / high |
| CWE-1321 | `rp.proto.computed-assign`, `rp.proto.proto-write` | `obj[key] = value` with tainted bare-identifier key and tainted value; writes through `__proto__` / `constructor.prototype` | high |
| CWE-611 | `rp.xxe.libxml-noent` | `libxmljs(2).parseXml/parseXmlString` with `noent: true` | high |
| CWE-502 | `rp.deser.unsafe`, `rp.deser.yaml-load` | `node-serialize.unserialize`, `serialize-to-js`, `funcster`, `js-yaml.load` | critical / medium |
| CWE-1333 | `rp.redos.dynamic-regex`, `rp.redos.evil-regex` | `RegExp(tainted)`; nested-quantifier regex literals (`([0-9]+)+`) applied to tainted input | medium |
| CWE-798 | `rp.secrets.hardcoded` | password/secret/apiKey/token-like names assigned string literals of 8+ characters (placeholders and `process.env` ignored) | medium |
| CWE-327 | `rp.crypto.weak-hash`, `rp.crypto.deprecated-cipher` | `crypto.createHash('md5'|'sha1')`, `md5()`/`sha1()` packages, `crypto.createCipher` | low / medium |
| CWE-295 | `rp.tls.reject-unauthorized` | `rejectUnauthorized: false` | medium |

Rules that need data flow fire only when the relevant arguments carry taint. Configuration rules (secrets, crypto, TLS) have taint `none`.

### 8. Merge and output
Findings are merged per `(function, CWE)`. The engine keeps the strongest evidence (`user_input` > `parameter` > `none`, then severity) and collects every related line. Each finding carries `call_path` and `taint_path`.

## Output schema (abridged)

```json
{
  "engine": "reachprioritizer-analyzer", "version": "2.0.0", "mode": "server",
  "stats": { "files_analyzed": 12, "functions": 25, "edges": 33, "findings": 9,
             "reachable": 16, "startup_only": 4, "unreachable": 5 },
  "entry_points": [ { "id": "src/app.js::__top_level__", "kind": "startup", "label": "package.json \"main\"", "active": true },
                    { "id": "src/controllers/fileController.js::downloadFile", "kind": "route", "label": "GET /download", "active": true, "registered_in": "src/routes/fileRoutes.js::__top_level__" } ],
  "nodes": [ { "id": "src/utils/merge.js::deepMerge", "name": "deepMerge", "file_path": "src/utils/merge.js",
               "start_line": 4, "end_line": 15, "node_type": "FunctionDeclaration", "params": ["target", "source"],
               "is_exported": true, "reachability": "reachable", "call_path": ["src/app.js::__top_level__", "…"],
               "entry": { "kind": "route", "label": "POST /settings" }, "source": "function deepMerge(…) {…}" } ],
  "edges": [ { "caller_id": "…", "callee_id": "…", "kind": "call", "line": 26 } ],
  "findings": [ { "rule_id": "rp.proto.computed-assign", "cwe": "CWE-1321", "severity": "high", "title": "Prototype pollution",
                  "file_path": "src/utils/merge.js", "line": 10, "function_id": "src/utils/merge.js::deepMerge",
                  "taint": "user_input", "taint_path": ["src/controllers/userController.js::updateSettings", "src/utils/merge.js::deepMerge"],
                  "reachability": "reachable", "call_path": ["…"], "related_lines": [8, 10], "message": "…" } ],
  "unresolved_calls": [ { "name": "res.json", "count": 6 } ], "parse_errors": [], "skipped_files": []
}
```

## Extending the engine

- **New sink:** add a branch in `matchCallSink` (`rules.js`) that returns `{ rule_id, cwe, title, severity, category, args }`, then add a focused test in `test/engine.test.js`.
- **New source or sanitizer:** extend `REQUEST_PROPS` / `isSourceChain` or `GENERIC_SANITIZER` in `rules.js`.
- **New framework entry point:** extend `detectRouteOrServer` (`file_analyzer.js`) or the platform conventions in `detectEntryPoints` (`project.js`).
- Run `npm run test:analyzer`, then `python evaluation/scripts/run_experiments.py`, to check for regressions.

## Known limitations
- Calls through computed properties (`obj[name]()`), dependency-injection containers, `eval`-generated code and monkey-patching are not resolved.
- Taint tracking is name-based and flow-insensitive within a function. Aliasing through object fields is approximated (a write to `obj.x` taints `obj`).
- Only one (shortest) call path is kept per function.
- Third-party code (`node_modules`) is not analyzed.
