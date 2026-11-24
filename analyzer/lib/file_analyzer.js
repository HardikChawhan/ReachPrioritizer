'use strict';
/**
 * Per-file analysis: functions, module bindings, exports, call sites, route
 * registrations, entry-point indicators and intra-procedural taint findings.
 */
const {
  parse, children, unwrap, isMember, isCall, isFunction, propName, memberChain,
  keyName, stringValue, isRequireCall, patternNames, isLiteral,
} = require('./ast');
const R = require('./rules');

const U = 'U';
const EMPTY = new Set();
const ROUTE_METHODS = new Set(['get', 'post', 'put', 'delete', 'del', 'patch', 'all', 'options', 'head', 'use']);
const CLIENT_MODULES = new Set(['axios', 'http', 'https', 'got', 'request', 'superagent', 'needle', 'node-fetch', 'undici', 'supertest']);
const CHECK_METHODS = new Set(['includes', 'has', 'test', 'startsWith', 'endsWith', 'indexOf', 'match', 'matches', 'hasOwnProperty', 'isSafeInteger', 'isInteger']);
const CHECK_FN = /^(is[A-Z_]|valid|check|verify|allow|whitelist|safe)/;
const NON_TAINT_METHODS = /^(test|includes|startsWith|endsWith|indexOf|lastIndexOf|has|hasOwnProperty|every|some|localeCompare|isArray|isInteger|isSafeInteger|isNaN|isFinite)$/;
const MAX_SOURCE = 20000;

function union(a, b) {
  if (!b || b.size === 0) return a;
  if (!a || a.size === 0) return b;
  const s = new Set(a);
  for (const x of b) s.add(x);
  return s;
}

function normalizeModule(spec) {
  if (!spec) return spec;
  let m = spec.replace(/^node:/, '');
  if (m === 'fs/promises') return 'fs';
  if (m === 'child_process/promises') return 'child_process';
  return m;
}

const isLocalSpec = (s) => typeof s === 'string' && (s.startsWith('.') || s.startsWith('/'));

function analyzeFile(relPath, source) {
  let ast;
  try {
    ast = parse(source, relPath);
  } catch (err) {
    return { relPath, error: `Parse error: ${err.message}` };
  }
  const lines = source.split(/\r?\n/);

  const F = {
    relPath,
    source,
    error: null,
    mounts: [],                 // app.use('/prefix', router) registrations
    portHints: [],              // numbers that look like the server port
    recoveredErrors: (ast.errors || []).length,
    lineCount: lines.length,
    functions: [],
    frames: [],
    frameById: new Map(),
    nodeToId: new Map(),
    bindings: new Map(),        // local name -> { module, member, local, alias }
    exportsMap: new Map(),      // export name -> descriptor
    starExports: [],
    classes: new Map(),         // class name -> { methods: Map(short -> id), ctor }
    varClass: new Map(),        // 'svc' | 'this.svc' -> class name
    objMethods: new Map(),      // 'app' -> Map(key -> id)
    bare: new Map(),            // bare callable name -> [ids]
    methods: new Map(),         // short name -> [ids]
    routes: [],
    serverRoots: [],
    indicators: { listen: false, createServer: false, requireMain: false },
    findings: [],
    callRecords: [],
    regexVars: new Map(),       // const re = /.../ -> pattern
  };

  collectBindings(ast, F);

  // ------------------------------------------------------------- main walk
  const top = newFrame(F, {
    id: `${relPath}::__top_level__`, name: '__top_level__', short: '__top_level__',
    node: ast, nodeType: 'Module', parent: null, startLine: 1, endLine: lines.length, params: [],
  });
  top.isModule = true;

  const frameStack = [top];
  const classStack = [];
  const anc = [];
  const ifStack = [];

  function curFrame() { return frameStack[frameStack.length - 1]; }
  function ifTestsFor(frame) {
    const out = [];
    for (const e of ifStack) if (e.frame === frame) out.push(e.test);
    return out;
  }

  function visit(node, key) {
    const parent = anc[anc.length - 1] || null;
    let pushedFrame = false;
    let pushedClass = false;
    const fr = curFrame();

    if (isFunction(node)) {
      const nf = createFunctionFrame(F, node, parent, key, anc, classStack, fr);
      frameStack.push(nf);
      pushedFrame = true;
    } else if (node.type === 'ClassDeclaration' || node.type === 'ClassExpression') {
      let cname = node.id ? node.id.name : null;
      if (!cname && parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') cname = parent.id.name;
      if (!cname && parent && parent.type === 'ExportDefaultDeclaration') cname = 'default';
      cname = cname || `<class:L${node.loc ? node.loc.start.line : 0}>`;
      if (!F.classes.has(cname)) F.classes.set(cname, { methods: new Map(), ctor: null, superClass: node.superClass ? memberChain(node.superClass) : null });
      classStack.push(cname);
      pushedClass = true;
    }

    const frame = curFrame();
    recordNode(F, node, parent, key, frame, ifTestsFor(frame), anc);

    anc.push(node);
    if (node.type === 'IfStatement') {
      visit(node.test, 'test');
      ifStack.push({ frame, test: node.test });
      visit(node.consequent, 'consequent');
      if (node.alternate) visit(node.alternate, 'alternate');
      ifStack.pop();
    } else if (node.type === 'ConditionalExpression') {
      visit(node.test, 'test');
      ifStack.push({ frame, test: node.test });
      visit(node.consequent, 'consequent');
      visit(node.alternate, 'alternate');
      ifStack.pop();
    } else {
      for (const [k, child] of children(node)) visit(child, k);
    }
    anc.pop();

    if (pushedFrame) frameStack.pop();
    if (pushedClass) classStack.pop();
  }

  visit(ast.program, 'program');

  for (const frame of F.frames) {
    if (frame.pendingSourceRange) {
      const [a, b] = frame.pendingSourceRange;
      frame.fn.source = source.slice(a, b).slice(0, MAX_SOURCE);
      delete frame.pendingSourceRange;
    }
  }

  collectExports(ast, F);
  for (const fn of F.functions) {
    fn.is_exported = isExportedFunction(F, fn);
  }

  // ------------------------------------------------------------- taint + rules
  for (const frame of F.frames) analyzeFrame(F, frame, lines);

  // strip AST references
  for (const frame of F.frames) {
    delete frame.node;
  }
  return F;
}

// ---------------------------------------------------------------------------
// Bindings (require / import)
// ---------------------------------------------------------------------------
function collectBindings(ast, F) {
  const visitAll = (node) => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'VariableDeclarator' && node.init) {
      const init = unwrap(node.init);
      let spec = null;
      let member = null;
      if (isRequireCall(init)) spec = stringValue(init.arguments[0]);
      else if (isMember(init) && isRequireCall(init.object)) { spec = stringValue(init.object.arguments[0]); member = propName(init); }
      else if (init && init.type === 'AwaitExpression' && init.argument && init.argument.type === 'ImportExpression') spec = stringValue(init.argument.source);
      if (spec != null) {
        const mod = isLocalSpec(spec) ? spec : normalizeModule(spec);
        if (node.id.type === 'Identifier') {
          F.bindings.set(node.id.name, { module: mod, member, local: isLocalSpec(spec) });
        } else if (node.id.type === 'ObjectPattern') {
          for (const p of node.id.properties) {
            if (p.type !== 'ObjectProperty') continue;
            const exported = keyName(p.key);
            const localNode = p.value && p.value.type === 'AssignmentPattern' ? p.value.left : p.value;
            if (localNode && localNode.type === 'Identifier') {
              F.bindings.set(localNode.name, { module: mod, member: member ? `${member}.${exported}` : exported, local: isLocalSpec(spec) });
            }
          }
        }
      } else if (node.id.type === 'Identifier' && isCall(init)) {
        // const run = util.promisify(cp.exec)  -> alias to child_process.exec
        const c = memberChain(init.callee);
        if (c && (c.join('.') === 'util.promisify' || c.join('.') === 'promisify') && init.arguments[0]) {
          const target = memberChain(init.arguments[0]);
          if (target) F.bindings.set(node.id.name, { aliasChain: target });
        }
      }
    }
    if (node.type === 'ImportDeclaration') {
      const spec = node.source.value;
      const mod = isLocalSpec(spec) ? spec : normalizeModule(spec);
      for (const s of node.specifiers || []) {
        if (s.type === 'ImportDefaultSpecifier') F.bindings.set(s.local.name, { module: mod, member: 'default', local: isLocalSpec(spec) });
        else if (s.type === 'ImportNamespaceSpecifier') F.bindings.set(s.local.name, { module: mod, member: null, local: isLocalSpec(spec), namespace: true });
        else if (s.type === 'ImportSpecifier') F.bindings.set(s.local.name, { module: mod, member: s.imported.name || s.imported.value, local: isLocalSpec(spec) });
      }
    }
    for (const [, c] of children(node)) visitAll(c);
  };
  visitAll(ast.program);
}

/** Canonical API name of a callee chain, e.g. ['cp','exec'] -> 'child_process.exec'. */
function canonicalName(F, chain, depth = 0) {
  if (!chain || chain.length === 0) return null;
  const b = F.bindings.get(chain[0]);
  if (!b) return chain.join('.');
  if (b.aliasChain && depth < 3) {
    const base = canonicalName(F, b.aliasChain, depth + 1);
    return [base, ...chain.slice(1)].join('.');
  }
  if (b.local) return chain.join('.');
  const parts = [b.module];
  if (b.member && b.member !== 'default') parts.push(b.member);
  return [...parts, ...chain.slice(1)].join('.');
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------
function newFrame(F, o) {
  const frame = {
    id: o.id,
    name: o.name,
    short: o.short || o.name,
    node: o.node,
    nodeType: o.nodeType,
    parent: o.parent,
    params: o.params || [],
    paramNames: (o.params || []).map((p) => patternNames(p)),
    className: o.className || null,
    calls: [],
    decls: [],
    assigns: [],
    loops: [],
    ifs: [],
    builds: [],
    props: [],
    memberAssigns: [],
    imports: [],
    T: null,
  };
  F.frames.push(frame);
  F.frameById.set(frame.id, frame);
  const fn = {
    id: o.id,
    name: o.name,
    short: frame.short,
    file_path: F.relPath,
    start_line: o.startLine,
    end_line: o.endLine,
    start_col: o.startCol || 0,
    node_type: o.nodeType,
    params: frame.paramNames.map((n) => n.join(', ') || '_'),
    class_name: frame.className,
    parent_id: o.parent ? o.parent.id : null,
    is_exported: false,
    source: o.source || '',
    loc: Math.max(1, (o.endLine || 1) - (o.startLine || 1) + 1),
  };
  F.functions.push(fn);
  frame.fn = fn;
  return frame;
}

function uniqueId(F, base, line, col) {
  let id = `${F.relPath}::${base}`;
  if (!F.frameById.has(id)) return id;
  id = `${F.relPath}::${base}#L${line}`;
  if (!F.frameById.has(id)) return id;
  return `${F.relPath}::${base}#L${line}:${col}`;
}

function routeLabel(call) {
  const callee = unwrap(call.callee);
  if (!isMember(callee)) return null;
  const m = propName(callee);
  if (!m || !ROUTE_METHODS.has(m)) return null;
  const first = stringValue(call.arguments[0]);
  if (first != null && (first.startsWith('/') || first === '*')) return `${m.toUpperCase()} ${first}`;
  if (m === 'use') return 'middleware';
  return null;
}

function createFunctionFrame(F, node, parent, key, anc, classStack, parentFrame) {
  const line = node.loc ? node.loc.start.line : 0;
  const endLine = node.loc ? node.loc.end.line : line;
  const col = node.loc ? node.loc.start.column : 0;
  const cls = classStack[classStack.length - 1] || null;
  let name = null;
  let short = null;
  let bare = false;
  let method = false;
  let objOwner = null;
  let objKey = null;
  let inClass = null;

  const gp = anc[anc.length - 2] || null;
  const ggp = anc[anc.length - 3] || null;

  if (node.type === 'FunctionDeclaration' && node.id) {
    name = node.id.name; bare = true;
  } else if (node.type === 'ClassMethod' || node.type === 'ClassPrivateMethod') {
    const k = keyName(node.key) || '<computed>';
    short = k; name = cls ? `${cls}.${k}` : k; method = true; inClass = cls;
  } else if (node.type === 'ObjectMethod') {
    name = keyName(node.key) || '<computed>'; method = true;
    objKey = name;
    if (parent && parent.type === 'ObjectExpression') objOwner = ownerOfObject(parent, gp);
  } else if (parent && parent.type === 'VariableDeclarator' && key === 'init' && parent.id.type === 'Identifier') {
    name = parent.id.name; bare = true;
  } else if (parent && parent.type === 'AssignmentExpression' && key === 'right') {
    const chain = memberChain(parent.left);
    if (chain) {
      if (chain[0] === 'module' && chain[1] === 'exports') name = chain.length === 2 ? 'module.exports' : chain.slice(2).join('.');
      else if (chain[0] === 'exports' && chain.length > 1) name = chain.slice(1).join('.');
      else if (chain[0] === 'this' && chain.length === 2) {
        // class field assignment, or ES5 constructor function: function Handler() { this.run = () => {} }
        let owner = cls;
        if (!owner && parentFrame && !parentFrame.isModule && parentFrame.fn && parentFrame.fn.bare) {
          owner = parentFrame.name;
          if (!F.classes.has(owner)) F.classes.set(owner, { methods: new Map(), ctor: parentFrame.id, superClass: null, es5: true });
        }
        name = owner ? `${owner}.${chain[1]}` : chain[1]; short = chain[1]; method = true; inClass = owner;
      }
      else name = chain.join('.');
      if (chain.length === 1) bare = true;
      if (chain.length >= 2 && !(chain[0] === 'module' || chain[0] === 'exports' || chain[0] === 'this')) {
        objOwner = chain.slice(0, -1).join('.'); objKey = chain[chain.length - 1];
      }
    }
  } else if (parent && parent.type === 'ObjectProperty' && key === 'value') {
    name = keyName(parent.key) || '<computed>'; method = true; objKey = name;
    if (gp && gp.type === 'ObjectExpression') objOwner = ownerOfObject(gp, ggp);
  } else if (parent && (parent.type === 'ClassProperty' || parent.type === 'ClassPrivateProperty') && key === 'value') {
    const k = keyName(parent.key) || '<computed>';
    short = k; name = cls ? `${cls}.${k}` : k; method = true; inClass = cls;
  } else if (parent && parent.type === 'ExportDefaultDeclaration') {
    name = node.id ? node.id.name : 'default'; bare = !!node.id;
  }
  if (!name && node.type === 'FunctionExpression' && node.id) name = node.id.name;
  if (!name && parent && (isCall(parent) || parent.type === 'NewExpression') && key === 'arguments') {
    const label = routeLabel(parent);
    if (label) name = `<${label} handler:L${line}>`;
    else {
      const c = memberChain(parent.callee);
      const pc = unwrap(parent.callee);
      const last = c ? c[c.length - 1] : (isMember(pc) ? propName(pc) : null);
      name = last ? `<${last} callback:L${line}>` : `<anonymous callback:L${line}>`;
    }
  }
  if (!name) name = `<anonymous:L${line}>`;
  if (!short) short = name.includes('.') && !name.startsWith('<') ? name.split('.').pop() : name;

  const id = uniqueId(F, name, line, col);
  const frame = newFrame(F, {
    id, name, short, node, nodeType: node.type, parent: parentFrame,
    startLine: line, endLine, startCol: col, params: node.params || [], className: inClass,
  });
  frame.fn.bare = bare;
  frame.fn.is_method = method;
  F.nodeToId.set(node, id);
  if (node.kind === 'constructor' && inClass) frame.isCtor = true;

  if (bare) push(F.bare, name, id);
  push(F.methods, short, id);
  if (inClass && F.classes.has(inClass)) {
    F.classes.get(inClass).methods.set(short, id);
    if (short === 'constructor') F.classes.get(inClass).ctor = id;
  }
  if (objOwner && objKey) {
    if (!F.objMethods.has(objOwner)) F.objMethods.set(objOwner, new Map());
    F.objMethods.get(objOwner).set(objKey, id);
  }
  frame.pendingSourceRange = [node.start, node.end];
  return frame;
}

function ownerOfObject(objExpr, parentOfObj) {
  if (!parentOfObj) return null;
  if (parentOfObj.type === 'VariableDeclarator' && parentOfObj.id.type === 'Identifier') return parentOfObj.id.name;
  if (parentOfObj.type === 'AssignmentExpression') {
    const c = memberChain(parentOfObj.left);
    if (c) return c.join('.');
  }
  return null;
}

function push(map, k, v) {
  if (!map.has(k)) map.set(k, []);
  map.get(k).push(v);
}

// ---------------------------------------------------------------------------
// Node recording (attaches interesting nodes to the enclosing frame)
// ---------------------------------------------------------------------------
function recordNode(F, node, parent, key, frame, ifTests, anc) {
  switch (node.type) {
    case 'CallExpression':
    case 'OptionalCallExpression':
    case 'NewExpression': {
      frame.calls.push({ node, ifTests });
      const callee = unwrap(node.callee);
      // require('./x') / import('./x')
      if (callee && callee.type === 'Identifier' && callee.name === 'require' && node.arguments.length) {
        const spec = stringValue(node.arguments[0]);
        if (spec) frame.imports.push({ spec, line: node.loc ? node.loc.start.line : 0 });
      }
      detectRouteOrServer(F, node, frame);
      const chain = memberChain(callee);
      if (chain && chain[chain.length - 1] === 'listen') {
        F.indicators.listen = true;
        const pn = portNumber(node.arguments[0]);
        if (pn) F.portHints.unshift(pn);
      }
      break;
    }
    case 'ImportExpression': {
      const spec = stringValue(node.source);
      if (spec) frame.imports.push({ spec, line: node.loc ? node.loc.start.line : 0 });
      break;
    }
    case 'ImportDeclaration':
    case 'ExportAllDeclaration':
      if (node.source) frame.imports.push({ spec: node.source.value, line: node.loc ? node.loc.start.line : 0 });
      break;
    case 'ExportNamedDeclaration':
      if (node.source) frame.imports.push({ spec: node.source.value, line: node.loc ? node.loc.start.line : 0 });
      break;
    case 'VariableDeclarator':
      frame.decls.push({ node, ifTests });
      if (node.id.type === 'Identifier' && /port/i.test(node.id.name)) { const pn = portNumber(node.init); if (pn) F.portHints.push(pn); }
      if (node.id.type === 'Identifier' && node.init && node.init.type === 'RegExpLiteral') F.regexVars.set(node.id.name, node.init.pattern);
      if (node.id.type === 'Identifier' && node.init) {
        const init = unwrap(node.init);
        if (init && init.type === 'NewExpression') {
          const c = memberChain(init.callee);
          if (c) F.varClass.set(node.id.name, c[c.length - 1] === c[0] ? c[0] : c.join('.'));
        }
      }
      break;
    case 'AssignmentExpression': {
      frame.assigns.push({ node, ifTests });
      const right = unwrap(node.right);
      const lc = memberChain(node.left);
      if (lc && right && right.type === 'NewExpression') {
        const c = memberChain(right.callee);
        if (c) F.varClass.set(lc.join('.'), c.join('.'));
      }
      break;
    }
    case 'ForInStatement':
    case 'ForOfStatement':
      frame.loops.push({ node, ifTests });
      break;
    case 'IfStatement':
      frame.ifs.push(node);
      break;
    case 'BinaryExpression':
      if (node.operator === '+' && !(parent && parent.type === 'BinaryExpression' && parent.operator === '+')) {
        frame.builds.push({ node, ifTests });
      }
      if (node.operator === '===' || node.operator === '==') {
        const l = memberChain(node.left);
        const r = memberChain(node.right);
        if ((l && l.join('.') === 'require.main' && r && r[0] === 'module') || (r && r.join('.') === 'require.main' && l && l[0] === 'module')) {
          F.indicators.requireMain = true;
        }
      }
      break;
    case 'TemplateLiteral':
      if (node.expressions.length && !(parent && parent.type === 'TaggedTemplateExpression')) {
        frame.builds.push({ node, ifTests });
      }
      break;
    case 'ObjectProperty':
      frame.props.push({ node, ifTests });
      if (/^port$/i.test(keyName(node.key) || '')) { const pn = portNumber(node.value); if (pn) F.portHints.push(pn); }
      break;
    default:
      break;
  }
}

/** 3000 / process.env.PORT || 3000 / Number(process.env.PORT) || 8080 -> number */
function portNumber(n) {
  n = unwrap(n);
  if (!n) return null;
  if (n.type === 'NumericLiteral' && n.value > 0 && n.value < 65536) return n.value;
  if (n.type === 'StringLiteral' && /^\d{2,5}$/.test(n.value)) return Number(n.value);
  if (n.type === 'LogicalExpression') return portNumber(n.right) || portNumber(n.left);
  return null;
}

function detectRouteOrServer(F, call, frame) {
  const callee = unwrap(call.callee);
  const chain = memberChain(callee);
  const canonical = chain ? canonicalName(F, chain) : null;
  const line = call.loc ? call.loc.start.line : 0;
  const args = call.arguments || [];

  // http.createServer(handler)
  if (canonical && /^(http|https|http2)\.(createServer|createSecureServer)$/.test(canonical)) {
    F.indicators.createServer = true;
    for (const a of args) {
      if (isFunction(a) || (a && a.type === 'Identifier') || isMember(a)) {
        F.serverRoots.push({ handler: a, registeredIn: frame.id, line, label: `${canonical}()` });
      }
    }
    return;
  }
  if (!isMember(callee)) return;
  const m = propName(callee);
  if (!m) return;
  const rootMod = chain ? canonicalName(F, [chain[0]]) : null;
  if (rootMod && CLIENT_MODULES.has(rootMod.split('.')[0])) return;

  // server.on('request', handler)
  if (m === 'on' && stringValue(args[0]) === 'request' && args[1]) {
    F.serverRoots.push({ handler: args[1], registeredIn: frame.id, line, label: "server.on('request')" });
    return;
  }
  // fastify.route({ method, url, handler }) / hapi server.route({ path, handler })
  if (m === 'route' && args.length === 1 && args[0] && args[0].type === 'ObjectExpression') {
    let handler = null; let url = null; let method = 'ROUTE';
    for (const p of args[0].properties) {
      const k = p.key ? keyName(p.key) : null;
      if (k === 'handler') handler = p.type === 'ObjectMethod' ? p : p.value;
      if (k === 'url' || k === 'path') url = stringValue(p.value);
      if (k === 'method') method = (stringValue(p.value) || 'ROUTE').toUpperCase();
    }
    if (handler) F.routes.push({ method, route: url || '<dynamic>', receiver: chain && chain.length > 1 ? chain.slice(0, -1).join('.') : null, handlers: [handler], registeredIn: frame.id, line });
    return;
  }
  if (!ROUTE_METHODS.has(m)) return;
  if (!args.length) return;
  const a0 = unwrap(args[0]);
  const first = stringValue(a0);
  const firstIsPath = (first != null && (first.startsWith('/') || first === '*')) ||
    (a0 && a0.type === 'RegExpLiteral') ||
    (a0 && a0.type === 'TemplateLiteral' && a0.quasis[0] && a0.quasis[0].value.cooked.startsWith('/')) ||
    (a0 && a0.type === 'ArrayExpression' && a0.elements.some((e) => (stringValue(e) || '').startsWith('/')));
  if (!firstIsPath && m !== 'use') return;
  if (firstIsPath && args.length < 2) return;
  const rest = firstIsPath ? args.slice(1) : args;
  const receiver = chain && chain.length > 1 ? chain.slice(0, -1).join('.') : null;
  // app.use('/api/files', fileRoutes) / app.use('/api', require('./routes'))
  if (m === 'use' && first != null && first.startsWith('/')) {
    for (const a of rest) {
      const u = unwrap(a);
      if (!u) continue;
      if (isRequireCall(u)) F.mounts.push({ prefix: first, spec: stringValue(u.arguments[0]), receiver, line });
      else if (u.type === 'Identifier' || isMember(u)) { const c = memberChain(u); if (c) F.mounts.push({ prefix: first, targetChain: c, receiver, line }); }
    }
  }
  const handlers = rest.filter((a) => a && (isFunction(a) || a.type === 'Identifier' || isMember(a) || (a.type === 'ArrayExpression')))
    .flatMap((a) => (a.type === 'ArrayExpression' ? a.elements.filter(Boolean) : [a]));
  if (!handlers.length) return;
  F.routes.push({
    method: m === 'use' ? 'USE' : m.toUpperCase(),
    route: first != null ? first : (firstIsPath ? '<dynamic>' : '*'),
    receiver,
    handlers,
    registeredIn: frame.id,
    line,
  });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
function collectExports(ast, F) {
  const setExp = (name, desc) => { if (!F.exportsMap.has(name)) F.exportsMap.set(name, desc); };

  const describeValue = (v) => {
    v = unwrap(v);
    if (!v) return null;
    if (v.type === 'Identifier') return { local: v.name };
    if (isFunction(v)) return { fnId: F.nodeToId.get(v) };
    if (v.type === 'ClassExpression') return { cls: v.id ? v.id.name : null };
    if (v.type === 'NewExpression') { const c = memberChain(v.callee); return c ? { instanceOf: c.join('.') } : null; }
    if (isCall(v)) return { callResult: true };
    return null;
  };

  const handleModuleExportsObject = (obj) => {
    for (const p of obj.properties) {
      if (p.type === 'SpreadElement') {
        const d = describeValue(p.argument);
        if (d && d.local) F.starExports.push({ local: d.local });
        continue;
      }
      const k = keyName(p.key);
      if (!k) continue;
      if (p.type === 'ObjectMethod') setExp(k, { fnId: F.nodeToId.get(p) });
      else {
        const d = describeValue(p.value);
        if (d) setExp(k, d);
      }
    }
  };

  const visitAll = (node) => {
    if (!node || typeof node !== 'object') return;
    switch (node.type) {
      case 'ExportNamedDeclaration': {
        const d = node.declaration;
        if (d) {
          if (d.type === 'FunctionDeclaration' && d.id) setExp(d.id.name, { local: d.id.name });
          else if (d.type === 'ClassDeclaration' && d.id) setExp(d.id.name, { cls: d.id.name });
          else if (d.type === 'VariableDeclaration') {
            for (const decl of d.declarations) for (const n of patternNames(decl.id)) setExp(n, { local: n });
          }
        }
        for (const s of node.specifiers || []) {
          const exported = s.exported ? (s.exported.name || s.exported.value) : null;
          if (!exported) continue;
          if (node.source) setExp(exported, { reexport: node.source.value, name: s.local ? (s.local.name || s.local.value) : 'default' });
          else setExp(exported, { local: s.local.name });
        }
        break;
      }
      case 'ExportAllDeclaration':
        F.starExports.push({ reexport: node.source.value });
        break;
      case 'ExportDefaultDeclaration': {
        const d = node.declaration;
        if (d.type === 'Identifier') setExp('default', { local: d.name });
        else if (d.type === 'ClassDeclaration' || d.type === 'ClassExpression') setExp('default', { cls: d.id ? d.id.name : 'default' });
        else if (isFunction(d)) setExp('default', { fnId: F.nodeToId.get(d) });
        else if (d.type === 'ObjectExpression') { handleModuleExportsObject(d); setExp('default', { object: true }); }
        else { const desc = describeValue(d); if (desc) setExp('default', desc); }
        break;
      }
      case 'AssignmentExpression': {
        const chain = memberChain(node.left);
        if (chain && chain[0] === 'module' && chain[1] === 'exports') {
          if (chain.length === 2) {
            const r = unwrap(node.right);
            if (r && r.type === 'ObjectExpression') { handleModuleExportsObject(r); setExp('default', { object: true }); }
            else { const d = describeValue(r); if (d) setExp('default', d); }
          } else if (chain.length === 3) {
            const d = describeValue(node.right); if (d) setExp(chain[2], d);
          }
        } else if (chain && chain[0] === 'exports' && chain.length === 2) {
          const d = describeValue(node.right); if (d) setExp(chain[1], d);
        }
        break;
      }
      default: break;
    }
    for (const [, c] of children(node)) {
      if (isFunction(c) && node.type !== 'ExportDefaultDeclaration' && node.type !== 'AssignmentExpression' && node.type !== 'ObjectProperty') continue;
      visitAll(c);
    }
  };
  visitAll(ast.program);
}

function isExportedFunction(F, fn) {
  for (const [, d] of F.exportsMap) {
    if (d.fnId === fn.id) return true;
    if (d.local && fn.bare && d.local === fn.name) return true;
    if (d.cls && fn.class_name === d.cls) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Taint analysis
// ---------------------------------------------------------------------------
function exits(stmt) {
  if (!stmt) return false;
  if (['ReturnStatement', 'ThrowStatement', 'ContinueStatement', 'BreakStatement'].includes(stmt.type)) return true;
  if (stmt.type === 'BlockStatement') return stmt.body.some((s) => ['ReturnStatement', 'ThrowStatement', 'ContinueStatement', 'BreakStatement'].includes(s.type));
  if (stmt.type === 'ExpressionStatement' && isCall(stmt.expression)) {
    const c = memberChain(stmt.expression.callee);
    return !!c && c.join('.') === 'process.exit';
  }
  return false;
}

/** Variables validated by a condition. mode = 'exit' (guard clause) | 'enter' (sink inside the branch). */
function checkedNames(test, mode, out = new Set()) {
  test = unwrap(test);
  if (!test) return out;
  if (test.type === 'LogicalExpression') { checkedNames(test.left, mode, out); checkedNames(test.right, mode, out); return out; }
  if (test.type === 'UnaryExpression' && test.operator === '!') { checkedNames(test.argument, mode, out); return out; }
  if (isCall(test)) {
    const callee = unwrap(test.callee);
    const chain = memberChain(callee);
    const last = chain ? chain[chain.length - 1] : (isMember(callee) ? propName(callee) : null);
    const isCheck = (last && CHECK_METHODS.has(last)) || (last && CHECK_FN.test(last)) || (chain && chain.join('.').endsWith('hasOwnProperty.call'));
    if (isCheck) {
      for (const a of test.arguments) { const c = memberChain(a); if (c) out.add(c.join('.')); }
      if (isMember(callee)) { const oc = memberChain(callee.object); if (oc) out.add(oc.join('.')); }
    }
    return out;
  }
  if (test.type === 'BinaryExpression') {
    const ops = mode === 'exit' ? ['!==', '!='] : ['===', '=='];
    if (ops.includes(test.operator)) {
      const l = unwrap(test.left); const r = unwrap(test.right);
      if (isLiteral(r) && !(r.type === 'Identifier')) { const c = memberChain(l); if (c) out.add(c.join('.')); }
      if (isLiteral(l) && !(l.type === 'Identifier')) { const c = memberChain(r); if (c) out.add(c.join('.')); }
    }
    // x.indexOf(...) === -1 etc.
    for (const side of [test.left, test.right]) if (isCall(unwrap(side))) checkedNames(side, mode, out);
  }
  return out;
}

function makeCtx(frame, pos, ifTests, category) {
  let checks = EMPTY;
  if (ifTests && ifTests.length) {
    checks = new Set();
    for (const t of ifTests) for (const n of checkedNames(t, 'enter')) checks.add(n);
  }
  return { T: frame.T, frame, pos, checks, category };
}

function isSanitizedVar(name, ctx) {
  if (ctx.checks.has(name)) return true;
  for (const g of ctx.frame.guards || []) if (g.name === name && g.pos < ctx.pos) return true;
  return false;
}

function taintOf(n, ctx, depth = 0) {
  n = unwrap(n);
  if (!n || depth > 60) return EMPTY;
  switch (n.type) {
    case 'Identifier':
      if (isSanitizedVar(n.name, ctx)) return EMPTY;
      return ctx.T.get(n.name) || EMPTY;
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const chain = memberChain(n);
      if (chain && isSanitizedVar(chain.join('.'), ctx)) return EMPTY;
      if (chain && R.isSourceChain(chain)) {
        // 'U' marks user input; the 'S|' label records WHICH input (for the attack simulator)
        return new Set([U, `S|${R.sourceLabel(chain)}`]);
      }
      const p = propName(n);
      if (p && R.NEUTRAL_PROPS.has(p)) return EMPTY;
      return taintOf(n.object, ctx, depth + 1);
    }
    case 'CallExpression':
    case 'OptionalCallExpression':
    case 'NewExpression': {
      const callee = unwrap(n.callee);
      const chain = memberChain(callee);
      if (chain && R.isSourceCall(chain)) return new Set([U, `S|${R.getterLabel(chain, stringValue((n.arguments || [])[0]))}`]);
      if (chain && R.isSanitizer(chain, ctx.category)) return EMPTY;
      let s = EMPTY;
      if (isMember(callee)) {
        const m = propName(callee);
        if (m && NON_TAINT_METHODS.test(m)) return EMPTY;
        if (m && R.isSanitizer([m], ctx.category)) return EMPTY;
        s = union(s, taintOf(callee.object, ctx, depth + 1));
      }
      for (const a of n.arguments || []) {
        if (isFunction(a)) continue;
        s = union(s, taintOf(a.type === 'SpreadElement' ? a.argument : a, ctx, depth + 1));
      }
      return s;
    }
    case 'BinaryExpression':
      if (n.operator === '+') return union(taintOf(n.left, ctx, depth + 1), taintOf(n.right, ctx, depth + 1));
      return EMPTY;
    case 'LogicalExpression':
      return union(taintOf(n.left, ctx, depth + 1), taintOf(n.right, ctx, depth + 1));
    case 'ConditionalExpression':
      return union(taintOf(n.consequent, ctx, depth + 1), taintOf(n.alternate, ctx, depth + 1));
    case 'TemplateLiteral': {
      let s = EMPTY;
      for (const e of n.expressions) s = union(s, taintOf(e, ctx, depth + 1));
      return s;
    }
    case 'ObjectExpression': {
      let s = EMPTY;
      for (const p of n.properties) {
        if (p.type === 'SpreadElement') s = union(s, taintOf(p.argument, ctx, depth + 1));
        else if (p.type === 'ObjectProperty') s = union(s, taintOf(p.value, ctx, depth + 1));
      }
      return s;
    }
    case 'ArrayExpression': {
      let s = EMPTY;
      for (const e of n.elements) if (e) s = union(s, taintOf(e.type === 'SpreadElement' ? e.argument : e, ctx, depth + 1));
      return s;
    }
    case 'AwaitExpression':
    case 'YieldExpression':
    case 'SpreadElement':
      return taintOf(n.argument, ctx, depth + 1);
    case 'AssignmentExpression':
      return taintOf(n.right, ctx, depth + 1);
    case 'SequenceExpression':
      return taintOf(n.expressions[n.expressions.length - 1], ctx, depth + 1);
    default:
      return EMPTY;
  }
}

function assignPattern(T, pattern, origins) {
  let changed = false;
  if (!origins || origins.size === 0) return false;
  // const { file, page } = req.query  ->  'S|query' becomes 'S|query.file' / 'S|query.page'
  if (pattern && pattern.type === 'ObjectPattern' && [...origins].some((o) => o.startsWith('S|') && !o.includes('.'))) {
    for (const p of pattern.properties) {
      if (p.type !== 'ObjectProperty') { if (assignPattern(T, p.argument || p, origins)) changed = true; continue; }
      const k = keyName(p.key);
      const refined = new Set([...origins].map((o) => (o.startsWith('S|') && !o.includes('.') && k ? `${o}.${k}` : o)));
      const target = p.value && p.value.type === 'AssignmentPattern' ? p.value.left : p.value;
      if (assignPattern(T, target, refined)) changed = true;
    }
    return changed;
  }
  for (const name of patternNames(pattern)) {
    const prev = T.get(name);
    const next = union(prev || EMPTY, origins);
    if (!prev || next.size !== prev.size) { T.set(name, next); changed = true; }
  }
  return changed;
}

function computeGuards(frame) {
  const guards = [];
  for (const ifn of frame.ifs) {
    if (!exits(ifn.consequent)) continue;
    for (const n of checkedNames(ifn.test, 'exit')) guards.push({ name: n, pos: ifn.start });
  }
  return guards;
}

function analyzeFrame(F, frame, lines) {
  const T = new Map();
  if (frame.parent && frame.parent.T) for (const [k, v] of frame.parent.T) T.set(k, v);
  frame.paramNames.forEach((names, i) => {
    for (const n of names) T.set(n, new Set([`P|${frame.id}|${i}`]));
  });
  frame.T = T;
  frame.guards = computeGuards(frame);

  for (let iter = 0; iter < 8; iter++) {
    let changed = false;
    for (const { node, ifTests } of frame.decls) {
      if (!node.init || isFunction(node.init)) continue;
      const o = taintOf(node.init, makeCtx(frame, node.start, ifTests, null));
      if (assignPattern(T, node.id, o)) changed = true;
    }
    for (const { node, ifTests } of frame.assigns) {
      if (isFunction(node.right)) continue;
      const o = taintOf(node.right, makeCtx(frame, node.start, ifTests, null));
      if (!o.size) continue;
      const left = unwrap(node.left);
      if (left.type === 'Identifier' || left.type === 'ObjectPattern' || left.type === 'ArrayPattern') {
        if (assignPattern(T, left, o)) changed = true;
      } else if (isMember(left)) {
        const chain = memberChain(left);
        const root = chain ? chain[0] : null;
        if (root && !['this', 'module', 'exports', 'window', 'global', 'globalThis', 'process'].includes(root)) {
          const prev = T.get(root) || EMPTY;
          const next = union(prev, o);
          if (next.size !== prev.size) { T.set(root, next); changed = true; }
        }
      }
    }
    for (const { node, ifTests } of frame.loops) {
      const o = taintOf(node.right, makeCtx(frame, node.start, ifTests, null));
      const left = node.left.type === 'VariableDeclaration' ? node.left.declarations[0].id : node.left;
      if (assignPattern(T, left, o)) changed = true;
    }
    if (!changed) break;
  }

  // per-call records (for interprocedural taint + call graph)
  for (const { node, ifTests } of frame.calls) {
    const ctx = makeCtx(frame, node.start, ifTests, null);
    const callee = unwrap(node.callee);
    const rec = {
      requireSpec: isRequireCall(callee) ? stringValue(callee.arguments[0]) : null,
      caller: frame.id,
      line: node.loc ? node.loc.start.line : 0,
      isNew: node.type === 'NewExpression',
      chain: memberChain(callee),
      iife: isFunction(callee) ? F.nodeToId.get(callee) : null,
      argOrigins: (node.arguments || []).map((a) => (isFunction(a) ? [] : [...taintOf(a.type === 'SpreadElement' ? a.argument : a, ctx)])),
      callbackChains: [],
      inlineFns: [],
    };
    // calls into npm packages (dependency reachability)
    if (rec.chain) {
      const b = F.bindings.get(rec.chain[0]);
      if (b && !b.local && !b.aliasChain && b.module) {
        rec.external = b.module;
        rec.api = canonicalName(F, rec.chain);
        rec.userArg = rec.argOrigins.some((o) => o.includes(U));
      }
    }
    for (const a of node.arguments || []) {
      if (isFunction(a)) rec.inlineFns.push(F.nodeToId.get(a));
      else {
        const c = memberChain(a);
        if (c) rec.callbackChains.push(c);
      }
    }
    F.callRecords.push(rec);
  }

  runRules(F, frame, lines);
}

// ---------------------------------------------------------------------------
// Security rules
// ---------------------------------------------------------------------------
function snippetAt(lines, line) {
  const t = (lines[line - 1] || '').trim();
  return t.length > 240 ? t.slice(0, 237) + '...' : t;
}

function addFinding(F, frame, lines, node, rule, origins, extra = {}) {
  const line = node.loc ? node.loc.start.line : 0;
  let taint = 'none';
  const params = [];
  if (origins && origins.size) {
    if (origins.has(U)) taint = 'user_input';
    else taint = 'parameter';
    for (const o of origins) if (o !== U && !o.startsWith('S|')) params.push(o);
  }
  F.findings.push({
    rule_id: rule.rule_id,
    cwe: rule.cwe,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    file_path: F.relPath,
    line,
    column: node.loc ? node.loc.start.column : 0,
    function_id: frame.id,
    function_name: frame.name,
    snippet: snippetAt(lines, line),
    taint,
    origins: origins ? [...origins].filter((o) => !o.startsWith('S|')) : [],
    sources: origins ? [...origins].filter((o) => o.startsWith('S|')).map((o) => o.slice(2)) : [],
    sink: extra.sink || null,
    template: extra.template || null,
    message: extra.message || rule.title,
  });
}

function describeOrigins(frame, origins) {
  if (origins.has(U)) return 'user-controlled input';
  for (const o of origins) {
    if (o.startsWith('S|')) continue;
    const [, fid, idx] = o.split('|');
    if (fid === frame.id) {
      const names = frame.paramNames[Number(idx)] || [];
      return `parameter '${names.join(', ') || idx}'`;
    }
    return 'a value captured from an enclosing function';
  }
  return 'a dynamic value';
}

function flattenPlus(n, out) {
  n = unwrap(n);
  if (n && n.type === 'BinaryExpression' && n.operator === '+') { flattenPlus(n.left, out); flattenPlus(n.right, out); }
  else out.push(n);
  return out;
}

function staticAndDynamic(node) {
  if (node.type === 'TemplateLiteral') {
    return { text: node.quasis.map((q) => q.value.cooked || '').join(' ${} '), dyn: node.expressions };
  }
  const parts = flattenPlus(node, []);
  const text = [];
  const dyn = [];
  for (const p of parts) {
    const s = stringValue(p);
    if (s != null) text.push(s);
    else if (p && p.type === 'TemplateLiteral') { text.push(p.quasis.map((q) => q.value.cooked || '').join(' ${} ')); dyn.push(...p.expressions); }
    else { text.push(' ${} '); dyn.push(p); }
  }
  return { text: text.join(''), dyn };
}

function isHtmlOrConcat(n) {
  n = unwrap(n);
  if (!n) return false;
  if ((n.type === 'BinaryExpression' && n.operator === '+') || n.type === 'TemplateLiteral') {
    return R.HTML_TEXT.test(staticAndDynamic(n).text);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Sink templates (attack simulator): the dangerous value with the attacker's
// part marked as {{INPUT}}, e.g.  SELECT * FROM users WHERE id = '{{INPUT}}'
// ---------------------------------------------------------------------------
function codeOf(F, n) {
  if (!n || n.start == null) return '?';
  const t = F.source.slice(n.start, n.end).replace(/\s+/g, ' ');
  return t.length > 48 ? `${t.slice(0, 45)}...` : t;
}

function renderTemplate(F, n, ctx, depth = 0) {
  n = unwrap(n);
  if (!n || depth > 4) return null;
  const part = (p) => {
    p = unwrap(p);
    const s = stringValue(p);
    if (s != null) return s;
    if (p && (p.type === 'TemplateLiteral' || p.type === 'Identifier' || isCall(p))) {
      const r = renderTemplate(F, p, ctx, depth + 1);
      if (r) return r;
    }
    return taintOf(p, ctx).size ? '{{INPUT}}' : `\${${codeOf(F, p)}}`;
  };
  let out;
  if (n.type === 'Identifier') {
    // follow `const sql = `...${term}...`` to the value that is actually used
    let best = null;
    for (const { node: d } of ctx.frame.decls || []) {
      if (d.id.type === 'Identifier' && d.id.name === n.name && d.init && d.start < ctx.pos && (!best || d.start > best.start)) best = d;
    }
    if (best) { const r = renderTemplate(F, best.init, ctx, depth + 1); if (r) return r; }
    return taintOf(n, ctx).size ? '{{INPUT}}' : null;
  }
  if (isCall(n)) {
    const c = memberChain(unwrap(n.callee));
    const last = c ? c[c.length - 1] : null;
    if (last === 'join' || last === 'resolve') {
      // path.join(base, input) -> ${base}/{{INPUT}}
      out = (n.arguments || []).map(part).join('/');
      return out.includes('{{INPUT}}') ? out : null;
    }
    return taintOf(n, ctx).size ? '{{INPUT}}' : null;
  }
  if (n.type === 'TemplateLiteral') {
    out = '';
    n.quasis.forEach((q, i) => {
      out += q.value.cooked || '';
      if (i < n.expressions.length) out += part(n.expressions[i]);
    });
  } else if (n.type === 'BinaryExpression' && n.operator === '+') {
    out = flattenPlus(n, []).map(part).join('');
  } else {
    out = taintOf(n, ctx).size ? '{{INPUT}}' : null;
  }
  if (out && out.length > 400) out = `${out.slice(0, 397)}...`;
  return out && out.includes('{{INPUT}}') ? out : null;
}

function runRules(F, frame, lines) {
  // ---- call sinks
  for (const { node, ifTests } of frame.calls) {
    const callee = unwrap(node.callee);
    let chain = memberChain(callee);
    let canonical = null;
    if (chain) canonical = canonicalName(F, chain);
    else if (isMember(callee) && isRequireCall(callee.object)) {
      const spec = normalizeModule(stringValue(callee.object.arguments[0]));
      chain = [spec, propName(callee)];
      canonical = chain.join('.');
    }
    const method = chain ? chain[chain.length - 1] : null;

    // crypto / weak hash (non-taint)
    if (canonical === 'crypto.createHash') {
      const alg = (stringValue(node.arguments[0]) || '').toLowerCase();
      if (alg === 'md5' || alg === 'sha1') {
        addFinding(F, frame, lines, node, { rule_id: 'rp.crypto.weak-hash', cwe: 'CWE-327', title: `Weak hash algorithm (${alg})`, severity: 'low', category: 'crypto' }, null, { sink: canonical });
      }
    }
    if (canonical === 'md5' || canonical === 'sha1') {
      addFinding(F, frame, lines, node, { rule_id: 'rp.crypto.weak-hash', cwe: 'CWE-327', title: `Weak hash algorithm (${canonical})`, severity: 'low', category: 'crypto' }, null, { sink: canonical });
    }
    // ReDoS: vulnerable regex literal applied to input
    if (isMember(callee)) {
      const m = propName(callee);
      const regexOf = (n) => { n = unwrap(n); if (!n) return null; if (n.type === 'RegExpLiteral') return n.pattern; if (n.type === 'Identifier' && F.regexVars.has(n.name)) return F.regexVars.get(n.name); return null; };
      let pattern = null; let input = null;
      if (m === 'test' || m === 'exec') { pattern = regexOf(callee.object); input = node.arguments[0]; }
      else if (['match', 'matchAll', 'replace', 'replaceAll', 'search', 'split'].includes(m)) { pattern = regexOf(node.arguments[0]); input = callee.object; }
      if (pattern && input && R.EVIL_REGEX.test(pattern)) {
        const o = taintOf(input, makeCtx(frame, node.start, ifTests, 'redos'));
        if (o.size) addFinding(F, frame, lines, node, { rule_id: 'rp.redos.evil-regex', cwe: 'CWE-1333', title: 'ReDoS: catastrophic-backtracking regex on input', severity: 'medium', category: 'redos' }, o, { sink: `/${pattern}/`, message: `${describeOrigins(frame, o)} is matched against /${pattern}/ (nested quantifier — ReDoS)` });
      }
    }
    if (canonical === 'crypto.createCipher' || canonical === 'crypto.createDecipher') {
      addFinding(F, frame, lines, node, { rule_id: 'rp.crypto.deprecated-cipher', cwe: 'CWE-327', title: 'Deprecated cipher API without IV', severity: 'medium', category: 'crypto' }, null, { sink: canonical });
    }

    if (!chain) continue;
    const sink = R.matchCallSink({ canonical, chain, method, isNew: node.type === 'NewExpression', node });
    if (!sink) continue;
    const ctx = makeCtx(frame, node.start, ifTests, sink.category);
    let origins = EMPTY;
    const idxs = sink.args === 'all' ? node.arguments.map((_, i) => i) : sink.args;
    for (const i of idxs) {
      let a = node.arguments[i];
      if (!a) continue;
      if (a.type === 'SpreadElement') a = a.argument;
      if (isFunction(a)) continue;
      if (sink.objectKey && unwrap(a).type === 'ObjectExpression') {
        for (const p of unwrap(a).properties) {
          if (p.type === 'ObjectProperty' && ['url', 'baseURL', 'uri', 'host', 'hostname'].includes(keyName(p.key))) origins = union(origins, taintOf(p.value, ctx));
        }
      } else {
        origins = union(origins, taintOf(a, ctx));
      }
    }
    if (!origins.size) continue;
    if (sink.requireUser && !origins.has(U)) continue;
    if (sink.requireDirectObject) {
      const a0 = unwrap(node.arguments[0]);
      const c0 = memberChain(a0);
      const direct = (c0 && R.isSourceChain(c0)) || (a0 && a0.type === 'ObjectExpression' && a0.properties.some((p) => p.type === 'ObjectProperty' && memberChain(p.value) && R.isSourceChain(memberChain(p.value))));
      if (!direct) continue;
    }
    if (sink.requireUserOrHtml && !origins.has(U) && !isHtmlOrConcat(node.arguments[0])) continue;
    const apiName = canonical || chain.join('.');
    let template = null;
    for (const i of idxs) {
      const a = node.arguments[i];
      if (!a || isFunction(a)) continue;
      template = renderTemplate(F, a.type === 'SpreadElement' ? a.argument : a, ctx);
      if (template) break;
    }
    addFinding(F, frame, lines, node, sink, origins, {
      sink: apiName,
      template,
      message: `${describeOrigins(frame, origins)} flows into ${apiName}() — ${sink.title}`,
    });
  }

  // ---- assignment sinks: innerHTML, prototype pollution, hardcoded secrets
  for (const { node, ifTests } of frame.assigns) {
    const left = unwrap(node.left);
    if (!isMember(left)) {
      if (left.type === 'Identifier') checkSecret(F, frame, lines, node, left.name, node.right);
      continue;
    }
    const prop = propName(left);
    const ctx = makeCtx(frame, node.start, ifTests, 'xss');
    if (prop === 'innerHTML' || prop === 'outerHTML') {
      const o = taintOf(node.right, ctx);
      if (o.size) addFinding(F, frame, lines, node, { rule_id: 'rp.xss.inner-html', cwe: 'CWE-79', title: `DOM cross-site scripting (${prop})`, severity: 'high', category: 'xss' }, o, { sink: prop, template: renderTemplate(F, node.right, ctx), message: `${describeOrigins(frame, o)} is written to ${prop}` });
      continue;
    }
    if (prop) checkSecret(F, frame, lines, node, prop, node.right);
    // prototype pollution: target[key] = value with attacker-controlled bare key
    const pctx = makeCtx(frame, node.start, ifTests, 'proto');
    if (left.computed) {
      const keyNode = unwrap(left.property);
      if (keyNode && keyNode.type === 'Identifier') {
        const ko = taintOf(keyNode, pctx);
        const vo = taintOf(node.right, pctx);
        if (ko.size && vo.size) {
          const o = union(ko, vo);
          addFinding(F, frame, lines, node, { rule_id: 'rp.proto.computed-assign', cwe: 'CWE-1321', title: 'Prototype pollution', severity: 'high', category: 'proto' }, o, {
            sink: 'obj[key] = value',
            message: `${describeOrigins(frame, ko)} is used as an object key without blocking __proto__/constructor — prototype pollution`,
          });
        }
      }
    }
    const lc = memberChain(left);
    if (lc && (lc.includes('__proto__') || (lc.includes('constructor') && lc.includes('prototype')))) {
      const vo = taintOf(node.right, pctx);
      if (vo.size) addFinding(F, frame, lines, node, { rule_id: 'rp.proto.proto-write', cwe: 'CWE-1321', title: 'Prototype pollution (__proto__ write)', severity: 'high', category: 'proto' }, vo, { sink: lc.join('.') });
    }
  }

  // ---- declarations: hardcoded secrets
  for (const { node } of frame.decls) {
    if (node.id.type === 'Identifier' && node.init) checkSecret(F, frame, lines, node, node.id.name, node.init);
  }
  // ---- object properties: secrets, TLS verification disabled, dangerouslySetInnerHTML
  for (const { node, ifTests } of frame.props) {
    const k = keyName(node.key);
    if (!k) continue;
    if (k === '$where' && node.value) {
      const o = taintOf(node.value, makeCtx(frame, node.start, ifTests, 'nosqli'));
      if (o.size) addFinding(F, frame, lines, node, { rule_id: 'rp.nosqli.where', cwe: 'CWE-943', title: 'NoSQL injection ($where JavaScript expression)', severity: 'high', category: 'nosqli' }, o, { sink: '$where', message: `${describeOrigins(frame, o)} is embedded in a MongoDB $where expression` });
    }
    if (k === 'rejectUnauthorized' && node.value && node.value.type === 'BooleanLiteral' && node.value.value === false) {
      addFinding(F, frame, lines, node, { rule_id: 'rp.tls.reject-unauthorized', cwe: 'CWE-295', title: 'TLS certificate verification disabled', severity: 'medium', category: 'tls' }, null, { sink: 'rejectUnauthorized: false' });
    }
    if (k === 'dangerouslySetInnerHTML' && node.value && node.value.type === 'ObjectExpression') {
      const ctx = makeCtx(frame, node.start, ifTests, 'xss');
      const o = taintOf(node.value, ctx);
      if (o.size) addFinding(F, frame, lines, node, { rule_id: 'rp.xss.react-dangerous-html', cwe: 'CWE-79', title: 'Cross-site scripting (dangerouslySetInnerHTML)', severity: 'high', category: 'xss' }, o, { sink: 'dangerouslySetInnerHTML' });
    }
    checkSecret(F, frame, lines, node, k, node.value);
  }

  // ---- string construction: SQL / HTML built from input
  for (const { node, ifTests } of frame.builds) {
    const { text, dyn } = staticAndDynamic(node);
    if (!dyn.length) continue;
    if (R.SQL_TEXT.test(text)) {
      const ctx = makeCtx(frame, node.start, ifTests, 'sqli');
      let o = EMPTY;
      for (const d of dyn) o = union(o, taintOf(d, ctx));
      if (o.size) {
        addFinding(F, frame, lines, node, { rule_id: 'rp.sqli.string-build', cwe: 'CWE-89', title: 'SQL injection (query built by string concatenation)', severity: 'high', category: 'sqli' }, o, {
          sink: 'SQL string',
          template: renderTemplate(F, node, ctx),
          message: `${describeOrigins(frame, o)} is concatenated into a SQL statement — use parameterized queries`,
        });
      }
    } else if (R.HTML_TEXT.test(text)) {
      const ctx = makeCtx(frame, node.start, ifTests, 'xss');
      let o = EMPTY;
      for (const d of dyn) o = union(o, taintOf(d, ctx));
      if (o.size) {
        addFinding(F, frame, lines, node, { rule_id: 'rp.xss.html-build', cwe: 'CWE-79', title: 'Cross-site scripting (HTML built from unescaped input)', severity: 'medium', category: 'xss' }, o, {
          sink: 'HTML string',
          template: renderTemplate(F, node, ctx),
          message: `${describeOrigins(frame, o)} is inserted into HTML without escaping`,
        });
      }
    }
  }
}

function checkSecret(F, frame, lines, node, name, valueNode) {
  if (!name || !R.SECRET_NAME.test(name)) return;
  const v = stringValue(valueNode);
  if (v == null || v.length < 8 || /\s/.test(v) || R.PLACEHOLDER.test(v) || v.includes('process.env')) return;
  addFinding(F, frame, lines, node, { rule_id: 'rp.secrets.hardcoded', cwe: 'CWE-798', title: 'Hardcoded credential', severity: 'medium', category: 'secrets' }, null, {
    sink: name,
    message: `Hardcoded value assigned to '${name}' — load secrets from environment or a vault`,
  });
}

module.exports = { analyzeFile, canonicalName, normalizeModule, isLocalSpec };
