'use strict';
/**
 * Project-level analysis:
 *   1. analyze every source file
 *   2. resolve calls / callbacks / imports into a cross-file call graph
 *   3. detect startup entry points and request entry points (route handlers)
 *   4. compute reachability with concrete call paths
 *   5. propagate taint across function boundaries (interprocedural)
 *   6. merge security findings per function
 */
const fs = require('fs');
const path = require('path');
const { analyzeFile, isLocalSpec } = require('./file_analyzer');
const { SEVERITY_RANK } = require('./rules');
const { memberChain } = require('./ast');

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', 'vendor', 'bower_components', '.nuxt', 'out', '.cache', '__MACOSX']);
// Test, tooling and documentation code is not part of the deployed attack surface.
const NON_PROD_DIRS = new Set(['test', 'tests', '__tests__', '__mocks__', 'spec', 'specs', 'cypress', 'e2e', 'fixtures', '__fixtures__', 'docs', 'examples', 'example', '.storybook', 'benchmark', 'benchmarks']);
const NON_PROD_FILE = /(\.(test|spec|e2e|cy|stories)\.[cm]?[jt]sx?$)|(^|\/)(Gruntfile|gulpfile|Gulpfile|webpack\.config|rollup\.config|vite\.config|vitest\.config|jest\.config|karma\.conf|babel\.config|eslint\.config|\.eslintrc|tailwind\.config|postcss\.config|next\.config|nuxt\.config|playwright\.config|cypress\.config)\.[cm]?[jt]s$/;
const SOURCE_EXT = /\.(js|mjs|cjs|jsx|ts|tsx|mts|cts)$/i;
const MAX_FILES = 3000;
const MAX_FILE_BYTES = 1024 * 1024;
const RESOLVE_EXT = ['', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts', '.json'];
const TAINT_RANK = { user_input: 2, parameter: 1, none: 0 };

function collectFiles(projectDir, options = {}) {
  const includeNonProd = !!options.includeTests;
  const out = [];
  const skipped = [];
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (out.length >= MAX_FILES) return;
      const abs = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith('.')) continue;
        if (!includeNonProd && NON_PROD_DIRS.has(e.name)) { skipped.push({ file: path.relative(projectDir, abs).split(path.sep).join('/') + '/', reason: 'test/tooling directory' }); continue; }
        walk(abs);
      } else if (e.isFile() && SOURCE_EXT.test(e.name) && !/\.min\.js$/i.test(e.name) && !/\.d\.ts$/i.test(e.name)) {
        let size = 0;
        try { size = fs.statSync(abs).size; } catch { continue; }
        const rel = path.relative(projectDir, abs).split(path.sep).join('/');
        if (!includeNonProd && NON_PROD_FILE.test(rel)) { skipped.push({ file: rel, reason: 'test/tooling file' }); continue; }
        if (size > MAX_FILE_BYTES) { skipped.push({ file: rel, reason: 'file too large' }); continue; }
        out.push(rel);
      }
    }
  };
  walk(projectDir);
  return { files: out, skipped };
}

function findPackageJsons(projectDir) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 3) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(path.join(dir, e.name), depth + 1);
      else if (e.isFile() && e.name === 'package.json') out.push(path.join(dir, e.name));
    }
  };
  walk(projectDir, 0);
  return out;
}

class Project {
  constructor(projectDir, options = {}) {
    this.dir = path.resolve(projectDir);
    this.options = options;
    this.files = new Map(); // rel -> analyzed file
    this.fileList = [];
    this.parseErrors = [];
    this.skipped = [];
    this.functionById = new Map();
    this.edges = [];
    this.edgeKeys = new Set();
    this.unresolved = new Map();
    this.importedBy = new Map();
  }

  run() {
    const { files, skipped } = collectFiles(this.dir, this.options);
    this.skipped = skipped;
    for (const rel of files) {
      let src;
      try { src = fs.readFileSync(path.join(this.dir, rel), 'utf8'); } catch (e) { this.parseErrors.push({ file: rel, error: e.message }); continue; }
      const res = analyzeFile(rel, src);
      if (res.error) { this.parseErrors.push({ file: rel, error: res.error }); continue; }
      if (res.recoveredErrors) this.parseErrors.push({ file: rel, error: `${res.recoveredErrors} recoverable syntax error(s)`, recovered: true });
      this.files.set(rel, res);
      this.fileList.push(rel);
      for (const fn of res.functions) this.functionById.set(fn.id, fn);
    }
    this.buildEdges();
    this.detectEntryPoints();
    this.computeReachability();
    this.propagateTaint();
    this.mergeFindings();
    return this.output();
  }

  // ------------------------------------------------------------ resolution
  resolveModule(fromRel, spec) {
    if (!isLocalSpec(spec)) return null;
    const base = spec.startsWith('/') ? spec.slice(1) : path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec));
    const candidates = [];
    for (const ext of RESOLVE_EXT) candidates.push(base + ext);
    for (const ext of RESOLVE_EXT.slice(1)) candidates.push(`${base}/index${ext}`);
    // TS ESM style: import './x.js' that is really x.ts
    if (/\.(m|c)?js$/.test(base)) {
      const stem = base.replace(/\.(m|c)?js$/, '');
      for (const ext of ['.ts', '.tsx', '.mts', '.cts']) candidates.push(stem + ext);
    }
    for (const c of candidates) if (this.files.has(c)) return c;
    return null;
  }

  lookupExport(rel, name, seen = new Set()) {
    const key = `${rel}#${name}`;
    if (seen.has(key)) return [];
    seen.add(key);
    const F = this.files.get(rel);
    if (!F) return [];
    const ex = F.exportsMap.get(name);
    if (ex) {
      const r = this.resolveDescriptor(F, ex, seen);
      if (r.length) return r;
    }
    if (name !== 'default') {
      const def = F.exportsMap.get('default');
      if (def) {
        if (def.instanceOf) {
          const r = this.classMethod(F, def.instanceOf, name);
          if (r.length) return r;
        }
        if (def.local) {
          const om = F.objMethods.get(def.local);
          if (om && om.has(name)) return [om.get(name)];
          const cls = F.varClass.get(def.local);
          if (cls) { const r = this.classMethod(F, cls, name); if (r.length) return r; }
          if (F.classes.has(def.local)) { const r = this.classMethod(F, def.local, name); if (r.length) return r; }
        }
        if (def.cls) { const r = this.classMethod(F, def.cls, name); if (r.length) return r; }
      }
      for (const st of F.starExports) {
        if (st.reexport) {
          const tgt = this.resolveModule(rel, st.reexport);
          if (tgt) { const r = this.lookupExport(tgt, name, seen); if (r.length) return r; }
        }
        if (st.local) {
          const om = F.objMethods.get(st.local);
          if (om && om.has(name)) return [om.get(name)];
        }
      }
      // CommonJS fallback: a top-level function / method with that name in the module
      const byName = (F.bare.get(name) || []).filter((id) => {
        const fn = this.functionById.get(id);
        return fn && (fn.parent_id === `${rel}::__top_level__`);
      });
      if (byName.length && (F.exportsMap.size === 0 || ex)) return byName;
    }
    return [];
  }

  resolveDescriptor(F, ex, seen) {
    if (ex.fnId) return [ex.fnId];
    if (ex.local) {
      const ids = F.bare.get(ex.local);
      if (ids && ids.length) return ids;
      if (F.classes.has(ex.local)) { const c = F.classes.get(ex.local); return c.ctor ? [c.ctor] : []; }
      const b = F.bindings.get(ex.local);
      if (b && b.local) {
        const tgt = this.resolveModule(F.relPath, b.module);
        if (tgt) return this.lookupExport(tgt, b.member && b.member !== 'default' ? b.member : 'default', seen);
      }
      return [];
    }
    if (ex.reexport) {
      const tgt = this.resolveModule(F.relPath, ex.reexport);
      return tgt ? this.lookupExport(tgt, ex.name || 'default', seen) : [];
    }
    if (ex.cls) { const c = F.classes.get(ex.cls); return c && c.ctor ? [c.ctor] : []; }
    return [];
  }

  /** Class methods, following an imported class if needed. */
  classMethod(F, clsName, method, depth = 0) {
    if (depth > 4 || !clsName) return [];
    const simple = clsName.split('.').pop();
    const c = F.classes.get(simple);
    if (c) {
      if (c.methods.has(method)) return [c.methods.get(method)];
      if (c.superClass) return this.classMethod(F, c.superClass.join('.'), method, depth + 1);
      return [];
    }
    const head = clsName.split('.')[0];
    const b = F.bindings.get(head);
    if (b && b.local) {
      const tgt = this.resolveModule(F.relPath, b.module);
      if (!tgt) return [];
      const T = this.files.get(tgt);
      const member = clsName.includes('.') ? clsName.split('.').slice(1).join('.') : (b.member && b.member !== 'default' ? b.member : 'default');
      const ex = T.exportsMap.get(member);
      if (ex && ex.cls) return this.classMethod(T, ex.cls, method, depth + 1);
      if (ex && ex.local && T.classes.has(ex.local)) return this.classMethod(T, ex.local, method, depth + 1);
      if (ex && ex.reexport) {
        const t2 = this.resolveModule(tgt, ex.reexport);
        if (t2) { const T2 = this.files.get(t2); const ex2 = T2.exportsMap.get(ex.name); if (ex2 && (ex2.cls || ex2.local)) return this.classMethod(T2, ex2.cls || ex2.local, method, depth + 1); }
      }
    }
    return [];
  }

  resolveChain(F, frameId, chain, isNew) {
    if (!chain || !chain.length) return [];
    const frame = F.frameById.get(frameId);
    const first = chain[0];
    const b0 = F.bindings.get(first);

    if (chain.length === 1) {
      if (isNew) {
        if (F.classes.has(first)) { const c = F.classes.get(first); return c.ctor ? [c.ctor] : []; }
        if (b0 && b0.local) {
          const r = this.classMethod(F, first, 'constructor');
          if (r.length) return r;
        }
      }
      const local = F.bare.get(first);
      if (local && local.length) return local;
      if (b0 && b0.local) {
        const tgt = this.resolveModule(F.relPath, b0.module);
        if (!tgt) return [];
        return this.lookupExport(tgt, b0.member && b0.member !== 'default' ? b0.member : 'default');
      }
      return [];
    }

    const method = chain[chain.length - 1];
    const prefix = chain.slice(0, -1).join('.');

    if (first === 'this') {
      const cls = frame && frame.className;
      if (chain.length === 2) {
        if (cls) { const r = this.classMethod(F, cls, method); if (r.length) return r; }
        const ownerObj = this.ownerObjectOf(F, frameId);
        if (ownerObj) { const om = F.objMethods.get(ownerObj); if (om && om.has(method)) return [om.get(method)]; }
        const sameObj = this.siblingMethods(F, frameId, method);
        if (sameObj.length) return sameObj;
        return [];
      }
      const vc = F.varClass.get(prefix);
      if (vc) return this.classMethod(F, vc, method);
      return [];
    }

    if (chain.length === 2 && b0 && b0.local) {
      const tgt = this.resolveModule(F.relPath, b0.module);
      if (!tgt) return [];
      if (b0.member && b0.member !== 'default') {
        const T = this.files.get(tgt);
        const ex = T.exportsMap.get(b0.member);
        if (ex && ex.instanceOf) return this.classMethod(T, ex.instanceOf, method);
        if (ex && ex.cls) return this.classMethod(T, ex.cls, method);
        if (ex && ex.local) {
          const om = T.objMethods.get(ex.local);
          if (om && om.has(method)) return [om.get(method)];
          const vc = T.varClass.get(ex.local);
          if (vc) return this.classMethod(T, vc, method);
          if (T.classes.has(ex.local)) return this.classMethod(T, ex.local, method);
        }
        return [];
      }
      return this.lookupExport(tgt, method);
    }
    const vc = F.varClass.get(prefix);
    if (vc) { const r = this.classMethod(F, vc, method); if (r.length) return r; }
    const om = F.objMethods.get(prefix);
    if (om && om.has(method)) return [om.get(method)];
    if (chain.length === 2 && F.classes.has(first)) return this.classMethod(F, first, method);
    return [];
  }

  ownerObjectOf(F, frameId) {
    for (const [owner, m] of F.objMethods) for (const [, id] of m) if (id === frameId) return owner;
    return null;
  }

  siblingMethods(F, frameId, method) {
    // object literal methods calling this.other() — find a method `method` sharing the same parent frame
    const fn = this.functionById.get(frameId);
    if (!fn) return [];
    const out = [];
    for (const id of F.methods.get(method) || []) {
      const f2 = this.functionById.get(id);
      if (f2 && f2.parent_id === fn.parent_id && f2.is_method) out.push(id);
    }
    return out;
  }

  addEdge(caller, callee, kind, line) {
    if (!caller || !callee || caller === callee) return;
    const k = `${caller}->${callee}`;
    if (this.edgeKeys.has(k)) return;
    this.edgeKeys.add(k);
    this.edges.push({ caller_id: caller, callee_id: callee, kind, line: line || 0 });
  }

  buildEdges() {
    for (const [rel, F] of this.files) {
      // imports: executing a module's import runs the imported module's top level
      for (const frame of F.frames) {
        for (const imp of frame.imports) {
          const tgt = this.resolveModule(rel, imp.spec);
          if (tgt) {
            this.addEdge(frame.id, `${tgt}::__top_level__`, 'import', imp.line);
            if (!this.importedBy.has(tgt)) this.importedBy.set(tgt, new Set());
            this.importedBy.get(tgt).add(rel);
          }
        }
      }
      for (const rec of F.callRecords) {
        rec.targets = [];
        if (rec.iife) { this.addEdge(rec.caller, rec.iife, 'call', rec.line); rec.targets.push(rec.iife); }
        if (rec.requireSpec) {
          // require('./routes')(app) — call the module's default export
          const tgt = this.resolveModule(rel, rec.requireSpec);
          if (tgt) for (const id of this.lookupExport(tgt, 'default')) { this.addEdge(rec.caller, id, 'call', rec.line); rec.targets.push(id); }
        }
        if (rec.chain) {
          const ids = this.resolveChain(F, rec.caller, rec.chain, rec.isNew);
          for (const id of ids) { this.addEdge(rec.caller, id, 'call', rec.line); rec.targets.push(id); }
          if (!ids.length && rec.chain[0] !== 'require') {
            const name = rec.chain.join('.');
            this.unresolved.set(name, (this.unresolved.get(name) || 0) + 1);
          }
        }
        for (const id of rec.inlineFns) if (id) this.addEdge(rec.caller, id, 'callback', rec.line);
        for (const c of rec.callbackChains) {
          for (const id of this.resolveChain(F, rec.caller, c, false)) this.addEdge(rec.caller, id, 'callback', rec.line);
        }
      }
    }
  }

  // ------------------------------------------------------------ entry points
  detectEntryPoints() {
    const startup = new Map(); // id -> reason
    const addStartup = (rel, reason) => {
      if (this.files.has(rel)) { const id = `${rel}::__top_level__`; if (!startup.has(id)) startup.set(id, reason); }
    };

    for (const pkgPath of findPackageJsons(this.dir)) {
      let pkg;
      try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch { continue; }
      const pdir = path.relative(this.dir, path.dirname(pkgPath)).split(path.sep).join('/');
      const rel = (p) => this.resolveModule(pdir ? `${pdir}/x.js` : 'x.js', p.startsWith('.') ? p : `./${p}`);
      if (typeof pkg.main === 'string') { const r = rel(pkg.main); if (r) addStartup(r, 'package.json "main"'); }
      if (pkg.bin) {
        const bins = typeof pkg.bin === 'string' ? [pkg.bin] : Object.values(pkg.bin);
        for (const b of bins) { const r = rel(b); if (r) addStartup(r, 'package.json "bin"'); }
      }
      for (const s of ['start', 'dev', 'serve']) {
        const cmd = pkg.scripts && pkg.scripts[s];
        if (typeof cmd !== 'string') continue;
        const m = cmd.match(/(?:node|nodemon|ts-node|tsx|bun)\s+(?:--?[\w-]+(?:=\S+)?\s+)*([^\s]+\.(?:m?js|cjs|ts))/);
        if (m) { const r = rel(m[1]); if (r) addStartup(r, `package.json scripts.${s}`); }
      }
    }
    for (const [rel, F] of this.files) {
      if (F.indicators.listen) addStartup(rel, 'server.listen() / app.listen()');
      else if (F.indicators.createServer) addStartup(rel, 'http.createServer()');
      else if (F.indicators.requireMain) addStartup(rel, 'require.main === module');
    }
    for (const ov of this.options.entryPoints || []) {
      const [file, fn] = ov.split(':');
      if (fn) { const id = `${file}::${fn}`; if (this.functionById.has(id)) startup.set(id, 'user override'); }
      else addStartup(file, 'user override');
    }

    // Request entry points: route handlers + server request callbacks
    this.computeMounts();
    const request = [];
    for (const [rel, F] of this.files) {
      for (const r of F.routes) {
        const full = typeof r.route === 'string' && r.route.startsWith('/') ? joinPath(this.prefixOf(rel, r.receiver), r.route) : r.route;
        for (const h of r.handlers) {
          const ids = this.handlerIds(F, r.registeredIn, h);
          for (const id of ids) request.push({ id, kind: 'route', label: `${r.method} ${full}`, method: r.method, path: full, registeredIn: r.registeredIn, file: rel, line: r.line });
        }
      }
      for (const s of F.serverRoots) {
        for (const id of this.handlerIds(F, s.registeredIn, s.handler)) request.push({ id, kind: 'server', label: s.label, registeredIn: s.registeredIn, file: rel, line: s.line });
      }
      // serverless / framework conventions (invoked by the platform)
      const handlerExport = F.exportsMap.get('handler');
      if (handlerExport) for (const id of this.resolveDescriptor(F, handlerExport, new Set())) request.push({ id, kind: 'platform', label: 'serverless handler', registeredIn: null, file: rel, line: 0 });
      if (/(^|\/)pages\/api\//.test(rel) || /(^|\/)app\/.*\/route\.(m?[jt]sx?)$/.test(rel)) {
        for (const name of ['default', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
          const d = F.exportsMap.get(name);
          if (d) for (const id of this.resolveDescriptor(F, d, new Set())) request.push({ id, kind: 'platform', label: `Next.js ${name === 'default' ? 'API' : name} route`, registeredIn: null, file: rel, line: 0 });
        }
      }
    }

    let mode = 'server';
    if (startup.size === 0) {
      // library / unknown layout: modules nobody imports are the roots
      for (const rel of this.fileList) {
        if (!this.importedBy.has(rel)) startup.set(`${rel}::__top_level__`, 'module not imported by other project files');
      }
      if (startup.size === 0) for (const rel of this.fileList) startup.set(`${rel}::__top_level__`, 'fallback: all modules');
      mode = request.length ? 'server' : 'library';
      if (!request.length) {
        // exported API of root modules is the attack surface of a library
        for (const id of startup.keys()) {
          const rel = id.split('::')[0];
          const F = this.files.get(rel);
          if (!F) continue;
          for (const fn of F.functions) if (fn.is_exported) request.push({ id: fn.id, kind: 'library', label: 'exported API', registeredIn: null, file: rel, line: fn.start_line });
        }
      }
    }
    this.mode = request.length ? mode : 'module';
    this.startupRoots = startup;
    this.requestRoots = request;
  }

  /** Where each router is mounted: app.use('/api/files', fileRoutes). */
  computeMounts() {
    this.mountsInto = new Map(); // `${rel}|${receiver or *}` -> [{prefix, fromRel, receiver}]
    const add = (key, m) => { if (!this.mountsInto.has(key)) this.mountsInto.set(key, []); this.mountsInto.get(key).push(m); };
    for (const [rel, F] of this.files) {
      for (const m of F.mounts || []) {
        const info = { prefix: m.prefix, fromRel: rel, receiver: m.receiver };
        if (m.spec) {
          const tgt = this.resolveModule(rel, m.spec);
          if (tgt) add(`${tgt}|*`, info);
        } else if (m.targetChain) {
          const b = F.bindings.get(m.targetChain[0]);
          if (b && b.local) {
            const tgt = this.resolveModule(rel, b.module);
            if (tgt) add(`${tgt}|*`, info);
          } else if (!b) {
            add(`${rel}|${m.targetChain.join('.')}`, info);
          }
        }
      }
    }
  }

  prefixOf(rel, receiver, depth = 0) {
    if (depth > 8 || !this.mountsInto) return '';
    const list = (receiver && this.mountsInto.get(`${rel}|${receiver}`)) || this.mountsInto.get(`${rel}|*`);
    if (!list || !list.length) return '';
    const m = list[0];
    if (m.fromRel === rel && m.receiver === receiver) return m.prefix;
    return joinPath(this.prefixOf(m.fromRel, m.receiver, depth + 1), m.prefix);
  }

  /** Port the server most likely listens on (for generated attack requests). */
  guessPort() {
    // database / cache ports often sit next to the app port in config files
    const DB_PORTS = new Set([3306, 5432, 27017, 6379, 1433, 1521, 9200, 5672, 11211, 26257]);
    const ok = (p) => !DB_PORTS.has(p);
    for (const F of this.files.values()) if (F.indicators.listen) { const p = F.portHints.find(ok); if (p) return p; }
    for (const F of this.files.values()) { const p = F.portHints.find(ok); if (p) return p; }
    return 3000;
  }

  /** npm packages the code calls, and from which functions (dependency reachability). */
  dependencyUsage() {
    const usage = new Map();
    for (const F of this.files.values()) {
      for (const rec of F.callRecords) {
        if (!rec.external) continue;
        const pkg = packageName(rec.external);
        if (!pkg || BUILTINS.has(pkg)) continue;
        if (!usage.has(pkg)) usage.set(pkg, []);
        const list = usage.get(pkg);
        if (list.length < 200) list.push({ caller: rec.caller, api: rec.api, line: rec.line, file: F.relPath, user_input: !!rec.userArg });
      }
      for (const fr of F.frameById.values()) {
        for (const imp of fr.imports || []) {
          const pkg = packageName(imp.spec);
          if (!pkg || BUILTINS.has(pkg) || imp.spec.startsWith('.')) continue;
          if (!usage.has(pkg)) usage.set(pkg, []);
          usage.get(pkg).push({ caller: fr.id, api: `import ${imp.spec}`, line: imp.line, file: F.relPath, user_input: false, import: true });
        }
      }
    }
    const out = {};
    for (const [pkg, uses] of usage) out[pkg] = uses;
    return out;
  }

  handlerIds(F, frameId, h) {
    if (!h) return [];
    if (h.type === 'ObjectMethod' || h.type === 'FunctionExpression' || h.type === 'ArrowFunctionExpression') {
      const id = F.nodeToId.get(h);
      return id ? [id] : [];
    }
    const c = memberChain(h);
    return c ? this.resolveChain(F, frameId, c, false) : [];
  }

  // ------------------------------------------------------------ reachability
  adjacency() {
    if (this._adj) return this._adj;
    const adj = new Map();
    for (const e of this.edges) {
      if (!adj.has(e.caller_id)) adj.set(e.caller_id, []);
      adj.get(e.caller_id).push(e.callee_id);
    }
    this._adj = adj;
    return adj;
  }

  bfs(sources) {
    const adj = this.adjacency();
    const parent = new Map();
    const queue = [];
    for (const s of sources) { if (!parent.has(s)) { parent.set(s, null); queue.push(s); } }
    for (let i = 0; i < queue.length; i++) {
      const n = queue[i];
      for (const m of adj.get(n) || []) {
        if (!parent.has(m)) { parent.set(m, n); queue.push(m); }
      }
    }
    return parent;
  }

  static pathTo(parent, node) {
    const out = [];
    let cur = node;
    let guard = 0;
    while (cur != null && guard++ < 500) { out.push(cur); cur = parent.get(cur); }
    return out.reverse();
  }

  computeReachability() {
    const startupParent = this.bfs([...this.startupRoots.keys()]);
    this.startupParent = startupParent;
    const active = this.requestRoots.filter((r) => r.registeredIn == null || startupParent.has(r.registeredIn));
    for (const r of this.requestRoots) r.active = r.registeredIn == null || startupParent.has(r.registeredIn);
    const rootInfo = new Map();
    for (const r of active) if (!rootInfo.has(r.id)) rootInfo.set(r.id, r);
    const requestParent = this.bfs([...rootInfo.keys()]);
    this.reach = new Map();

    for (const id of this.functionById.keys()) {
      if (this.mode !== 'module' && requestParent.has(id)) {
        const tail = Project.pathTo(requestParent, id);
        const root = rootInfo.get(tail[0]);
        let prefix = [];
        if (root && root.registeredIn && startupParent.has(root.registeredIn)) prefix = Project.pathTo(startupParent, root.registeredIn);
        const full = [...prefix];
        for (const n of tail) if (!full.includes(n)) full.push(n);
        this.reach.set(id, { status: 'reachable', path: full, entry: root ? { kind: root.kind, label: root.label, method: root.method || null, path: root.path || null } : null });
      } else if (startupParent.has(id)) {
        this.reach.set(id, {
          status: this.mode === 'module' ? 'reachable' : 'startup_only',
          path: Project.pathTo(startupParent, id),
          entry: { kind: 'startup', label: this.startupRoots.get(Project.pathTo(startupParent, id)[0]) || 'startup' },
        });
      } else {
        this.reach.set(id, { status: 'unreachable', path: [], entry: null });
      }
    }
  }

  // ------------------------------------------------------------ interprocedural taint
  propagateTaint() {
    this.allFindings = [];
    const sinkDeps = new Map(); // `${fid}|${i}` -> [finding]
    for (const F of this.files.values()) {
      for (const f of F.findings) {
        this.allFindings.push(f);
        for (const o of f.origins) {
          if (!o.startsWith('P|')) continue;
          const [, fid, i] = o.split('|');
          const k = `${fid}|${i}`;
          if (!sinkDeps.has(k)) sinkDeps.set(k, []);
          sinkDeps.get(k).push(f);
        }
      }
    }
    const flows = new Map(); // key -> [{to, caller, line}]
    const seeds = []; // {key, caller, line}
    for (const F of this.files.values()) {
      for (const rec of F.callRecords) {
        if (!rec.targets || !rec.targets.length) continue;
        for (const t of rec.targets) {
          const fn = this.functionById.get(t);
          if (!fn || fn.node_type === 'Module') continue;
          rec.argOrigins.forEach((origins, i) => {
            const k = `${t}|${i}`;
            for (const o of origins) {
              if (o === 'U') seeds.push({ key: k, caller: rec.caller, line: rec.line, sources: origins.filter((x) => x.startsWith('S|')).map((x) => x.slice(2)) });
              else if (o.startsWith('P|')) {
                const [, pf, pi] = o.split('|');
                const from = `${pf}|${pi}`;
                if (!flows.has(from)) flows.set(from, []);
                flows.get(from).push({ to: k, caller: rec.caller, line: rec.line });
              }
            }
          });
        }
      }
    }
    // BFS over parameter flows from user-input call sites
    const pred = new Map();
    const queue = [];
    for (const s of seeds) if (!pred.has(s.key)) { pred.set(s.key, { from: null, caller: s.caller, line: s.line, sources: s.sources }); queue.push(s.key); }
    for (let i = 0; i < queue.length; i++) {
      const k = queue[i];
      for (const f of flows.get(k) || []) {
        if (!pred.has(f.to)) { pred.set(f.to, { from: k, caller: f.caller, line: f.line }); queue.push(f.to); }
      }
    }
    for (const [k, info] of pred) {
      for (const f of sinkDeps.get(k) || []) {
        if (f.taint === 'user_input') continue;
        // reconstruct the function chain that carries the input
        const chain = [];
        const hops = [];
        let cur = k; let guard = 0; let sources = [];
        while (cur && guard++ < 50) {
          const p = pred.get(cur);
          chain.push(p.caller);
          hops.push({ caller: p.caller, line: p.line });
          if (!p.from) sources = p.sources || [];
          cur = p.from;
        }
        f.sources = sources;
        f.taint_hops = hops.reverse();
        chain.reverse();
        chain.push(f.function_id);
        f.taint = 'user_input';
        f.taint_path = [...new Set(chain)];
        f.message = f.message.replace(/^(parameter '[^']*'|a value captured from an enclosing function)/, `user input (via ${this.shortName(chain[0])})`);
      }
    }
  }

  shortName(id) {
    const fn = this.functionById.get(id);
    return fn ? fn.name : id;
  }

  mergeFindings() {
    const byKey = new Map();
    for (const f of this.allFindings) {
      const k = `${f.function_id}|${f.cwe}`;
      const prev = byKey.get(k);
      if (!prev) { byKey.set(k, { ...f, related_lines: [f.line] }); continue; }
      prev.related_lines.push(f.line);
      const better = (TAINT_RANK[f.taint] - TAINT_RANK[prev.taint]) || (SEVERITY_RANK[f.severity] - SEVERITY_RANK[prev.severity]);
      if (better > 0) byKey.set(k, { ...f, related_lines: prev.related_lines });
    }
    this.findings = [...byKey.values()].map((f) => {
      const r = this.reach.get(f.function_id) || { status: 'unknown', path: [] };
      const { origins, ...rest } = f;
      return {
        ...rest,
        related_lines: [...new Set(rest.related_lines)].sort((a, b) => a - b),
        taint_path: f.taint_path || [f.function_id],
        reachability: r.status,
        call_path: r.path,
      };
    });
    this.findings.sort((a, b) => (a.file_path.localeCompare(b.file_path)) || (a.line - b.line));
  }

  output() {
    const withSource = !!this.options.withSource;
    const nodes = [];
    for (const F of this.files.values()) {
      for (const fn of F.functions) {
        const r = this.reach.get(fn.id) || { status: 'unknown', path: [] };
        const n = {
          id: fn.id, name: fn.name, short: fn.short, file_path: fn.file_path,
          start_line: fn.start_line, end_line: fn.end_line, node_type: fn.node_type,
          params: fn.params, class_name: fn.class_name, parent_id: fn.parent_id,
          is_exported: !!fn.is_exported, loc: fn.loc,
          reachability: r.status, call_path: r.path, entry: r.entry,
        };
        if (withSource) n.source = fn.source;
        nodes.push(n);
      }
    }
    const counts = { reachable: 0, startup_only: 0, unreachable: 0 };
    for (const n of nodes) if (n.node_type !== 'Module') counts[n.reachability] = (counts[n.reachability] || 0) + 1;
    const entryPoints = [
      ...[...this.startupRoots.entries()].map(([id, reason]) => ({ id, kind: 'startup', label: reason, active: true, file: id.split('::')[0], line: 1 })),
      ...this.requestRoots.map((r) => ({ id: r.id, kind: r.kind, label: r.label, method: r.method || null, path: r.path || null, active: !!r.active, file: r.file, line: r.line, registered_in: r.registeredIn })),
    ];
    const unresolved = [...this.unresolved.entries()].sort((a, b) => b[1] - a[1]).slice(0, 50).map(([name, count]) => ({ name, count }));
    return {
      engine: 'reachprioritizer-analyzer',
      version: '2.0.0',
      project_dir: this.dir,
      generated_at: new Date().toISOString(),
      mode: this.mode,
      server: { port: this.guessPort() },
      dependency_usage: this.dependencyUsage(),
      stats: {
        files_found: this.fileList.length + this.parseErrors.filter((e) => !e.recovered).length,
        files_analyzed: this.fileList.length,
        parse_errors: this.parseErrors.filter((e) => !e.recovered).length,
        functions: nodes.filter((n) => n.node_type !== 'Module').length,
        modules: nodes.filter((n) => n.node_type === 'Module').length,
        edges: this.edges.length,
        entry_points: entryPoints.length,
        findings: this.findings.length,
        ...counts,
      },
      parse_errors: this.parseErrors,
      skipped_files: this.skipped,
      entry_points: entryPoints,
      nodes,
      edges: this.edges,
      findings: this.findings,
      unresolved_calls: unresolved,
    };
  }
}

function joinPath(a, b) {
  const left = (a || '').replace(/\/+$/, '');
  if (!b || b === '/') return left || '/';
  return `${left}${b.startsWith('/') ? '' : '/'}${b}`;
}

const BUILTINS = new Set(['fs', 'path', 'os', 'http', 'https', 'http2', 'net', 'tls', 'dns', 'url', 'util', 'crypto', 'child_process', 'events',
  'stream', 'zlib', 'querystring', 'buffer', 'assert', 'vm', 'cluster', 'worker_threads', 'readline', 'process', 'timers', 'string_decoder', 'module', 'perf_hooks', 'v8', 'tty', 'dgram']);

function packageName(spec) {
  if (!spec || spec.startsWith('.') || spec.startsWith('/')) return null;
  const s = spec.replace(/^node:/, '');
  const parts = s.split('/');
  return s.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

function analyzeProject(projectDir, options = {}) {
  return new Project(projectDir, options).run();
}

module.exports = { analyzeProject, collectFiles };
