'use strict';
/**
 * Security knowledge base: taint sources, sanitizers and sinks for JavaScript / Node.js.
 *
 * A finding is produced when data from a SOURCE (user input) or from a function
 * PARAMETER reaches a SINK (dangerous API) without passing through a SANITIZER.
 */

// ---------------------------------------------------------------- sources
const REQUEST_ROOTS = new Set(['req', 'request', 'ctx', 'context', 'event']);
const REQUEST_PROPS = new Set([
  'body', 'query', 'params', 'headers', 'cookies', 'signedCookies', 'url', 'originalUrl',
  'path', 'files', 'file', 'hostname', 'rawBody', 'search', 'querystring',
  // AWS Lambda event shapes
  'queryStringParameters', 'pathParameters', 'multiValueQueryStringParameters',
]);
const REQUEST_GETTERS = new Set(['get', 'header', 'param', 'cookie']);

/** Is the static member chain a user-controlled value? */
function isSourceChain(chain) {
  if (!chain || chain.length < 2) return false;
  const [root, p1, p2] = chain;
  if (REQUEST_ROOTS.has(root)) {
    if (root === 'event' && !['body', 'queryStringParameters', 'pathParameters', 'headers', 'multiValueQueryStringParameters'].includes(p1)) return false;
    if (REQUEST_PROPS.has(p1)) return true;
    if ((root === 'ctx' || root === 'context') && p1 === 'request' && REQUEST_PROPS.has(p2)) return true;
  }
  if (root === 'process' && p1 === 'argv') return true;
  if ((root === 'location' || (root === 'window' && p1 === 'location') || (root === 'document' && p1 === 'location'))) return true;
  if (root === 'document' && (p1 === 'cookie' || p1 === 'URL' || p1 === 'referrer')) return true;
  return false;
}

/**
 * Short, human label for a source chain, used by the attack simulator:
 *   req.query.file -> 'query.file', ctx.request.body.name -> 'body.name',
 *   req.query -> 'query', process.argv -> 'argv'.
 */
function sourceLabel(chain) {
  if (!chain || !chain.length) return 'input';
  if (REQUEST_ROOTS.has(chain[0])) {
    for (let i = 1; i < Math.min(chain.length, 3); i++) {
      if (REQUEST_PROPS.has(chain[i])) return chain.slice(i, i + 2).join('.');
    }
  }
  if (chain[0] === 'process') return 'argv';
  if (chain[0] === 'document' && chain[1] === 'cookie') return 'cookie';
  return 'location';
}

/** Label for req.get('x-api-key') / req.param('id') style getters. */
function getterLabel(chain, firstArg) {
  const g = chain[chain.length - 1];
  const name = firstArg || '';
  if (g === 'get' || g === 'header') return name ? `headers.${name.toLowerCase()}` : 'headers';
  if (g === 'cookie') return name ? `cookies.${name}` : 'cookies';
  return name ? `param.${name}` : 'param';
}

/** req.get('x') / req.header('x') / req.param('x') */
function isSourceCall(chain) {
  return !!chain && chain.length === 2 && REQUEST_ROOTS.has(chain[0]) && REQUEST_GETTERS.has(chain[1]) && chain[0] !== 'event';
}

// ---------------------------------------------------------------- sanitizers
const GENERIC_SANITIZER = /^(escape|sanitize|sanitise|encode|purify|xss|filterXSS|stripTags|strip_tags|shellescape|shellEscape|shellQuote|quote|parseInt|parseFloat|Number|Boolean|basename|isValid|validate|uuidValidate|escapeId|toInteger|toNumber|toInt|toFloat)/i;
const XSS_ONLY_SANITIZERS = new Set(['JSON.stringify']);

function isSanitizer(chain, category) {
  if (!chain) return false;
  const last = chain[chain.length - 1];
  const full = chain.join('.');
  if (category === 'xss' && XSS_ONLY_SANITIZERS.has(full)) return true;
  if (full === 'path.basename') return true;
  if (full === 'Math.floor' || full === 'Math.round' || full === 'Math.abs') return true;
  return GENERIC_SANITIZER.test(last);
}

// Property reads that turn a tainted value into something harmless.
const NEUTRAL_PROPS = new Set(['length', 'size']);

// ---------------------------------------------------------------- sinks
const FS_PATH_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  'createReadStream', 'createWriteStream', 'unlink', 'unlinkSync', 'readdir', 'readdirSync',
  'rm', 'rmSync', 'rmdir', 'rmdirSync', 'open', 'openSync', 'copyFile', 'copyFileSync',
  'rename', 'renameSync', 'mkdir', 'mkdirSync', 'access', 'accessSync', 'stat', 'statSync',
  'existsSync', 'outputFile', 'readJson', 'readJsonSync', 'remove', 'removeSync',
]);
const FS_MODULES = new Set(['fs', 'fs/promises', 'fs-extra', 'graceful-fs']);
const RESPONSE_ROOTS = new Set(['res', 'response', 'reply', 'ctx', 'h']);
const SQL_METHODS = new Set(['query', 'execute', 'raw', 'unsafe', '$queryRawUnsafe', '$executeRawUnsafe', 'sql']);
const NOSQL_METHODS = new Set(['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'where', 'aggregate', 'countDocuments']);
const HTTP_CLIENTS = {
  http: new Set(['get', 'request']),
  https: new Set(['get', 'request']),
  axios: new Set(['', 'get', 'post', 'put', 'delete', 'patch', 'head', 'request', 'options']),
  got: new Set(['', 'get', 'post', 'put', 'delete', 'patch', 'stream']),
  request: new Set(['', 'get', 'post', 'put', 'delete', 'patch']),
  'node-fetch': new Set(['']),
  'cross-fetch': new Set(['']),
  undici: new Set(['request', 'fetch', 'stream']),
  superagent: new Set(['get', 'post', 'put', 'delete', '']),
  needle: new Set(['get', 'post', 'put', 'delete', 'request', '']),
};

// Nested quantifier such as ([0-9]+)+ or (a*)* -> catastrophic backtracking
const EVIL_REGEX = /\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)[+*{]/;

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Describe the sink for a call. `info` = { canonical, chain, method, isNew, node }.
 * Returns { rule_id, cwe, title, severity, category, args: [indices] | 'all', requireUser?, objectKey? } or null.
 */
function matchCallSink(info) {
  const { canonical, chain, method, isNew, node } = info;
  const raw = chain ? chain.join('.') : null;
  const root = chain ? chain[0] : null;
  const nargs = node.arguments ? node.arguments.length : 0;

  // ---- command injection
  if (canonical === 'child_process.exec' || canonical === 'child_process.execSync' || canonical === 'shelljs.exec') {
    return { rule_id: 'rp.cmdi.shell-exec', cwe: 'CWE-78', title: 'OS command injection', severity: 'critical', category: 'cmdi', args: [0] };
  }
  if (['child_process.spawn', 'child_process.spawnSync', 'child_process.execFile', 'child_process.execFileSync', 'child_process.fork'].includes(canonical)) {
    const shell = node.arguments.some((a) => a && a.type === 'ObjectExpression' && a.properties.some((p) => p.key && (p.key.name === 'shell' || p.key.value === 'shell') && p.value && p.value.type === 'BooleanLiteral' && p.value.value));
    return { rule_id: shell ? 'rp.cmdi.spawn-shell' : 'rp.cmdi.spawn-binary', cwe: 'CWE-78', title: shell ? 'OS command injection (shell: true)' : 'Attacker-controlled executable', severity: shell ? 'critical' : 'high', category: 'cmdi', args: shell ? [0, 1] : [0] };
  }

  // ---- code injection
  if (raw === 'eval' && canonical === 'eval') {
    return { rule_id: 'rp.code.eval', cwe: 'CWE-94', title: 'Code injection via eval()', severity: 'critical', category: 'code', args: [0] };
  }
  if ((raw === 'Function' || raw === 'global.Function' || raw === 'globalThis.Function') && canonical === raw) {
    return { rule_id: 'rp.code.function-constructor', cwe: 'CWE-94', title: 'Code injection via Function constructor', severity: 'critical', category: 'code', args: 'all' };
  }
  if (canonical && /^vm\.(runInNewContext|runInThisContext|runInContext|compileFunction|Script)$/.test(canonical)) {
    return { rule_id: 'rp.code.vm', cwe: 'CWE-94', title: 'Code injection via vm module', severity: 'critical', category: 'code', args: [0] };
  }
  if ((raw === 'setTimeout' || raw === 'setInterval') && nargs > 0) {
    const a0 = node.arguments[0];
    if (a0 && !['FunctionExpression', 'ArrowFunctionExpression', 'Identifier', 'MemberExpression'].includes(a0.type)) {
      return { rule_id: 'rp.code.timer-string', cwe: 'CWE-94', title: 'Code injection via string timer', severity: 'high', category: 'code', args: [0] };
    }
  }

  if (canonical === 'mathjs.eval' || canonical === 'mathjs.evaluate') {
    return { rule_id: 'rp.code.mathjs-eval', cwe: 'CWE-94', title: 'Code injection via mathjs.eval()', severity: 'critical', category: 'code', args: [0] };
  }

  // ---- XML external entities
  if (canonical && /^libxmljs2?\.(parseXml|parseXmlString)$/.test(canonical)) {
    const opts = node.arguments[1];
    const noent = opts && opts.type === 'ObjectExpression' && opts.properties.some((p) => p.key && (p.key.name === 'noent' || p.key.value === 'noent') && p.value && p.value.type === 'BooleanLiteral' && p.value.value);
    if (noent) return { rule_id: 'rp.xxe.libxml-noent', cwe: 'CWE-611', title: 'XML external entity (XXE) injection', severity: 'high', category: 'xxe', args: [0] };
  }

  // ---- deserialization
  if (canonical === 'node-serialize.unserialize' || canonical === 'serialize-to-js.deserialize' || canonical === 'funcster.deepDeserialize') {
    return { rule_id: 'rp.deser.unsafe', cwe: 'CWE-502', title: 'Unsafe deserialization', severity: 'critical', category: 'deser', args: [0] };
  }
  if (canonical === 'js-yaml.load' || canonical === 'yaml.load') {
    return { rule_id: 'rp.deser.yaml-load', cwe: 'CWE-502', title: 'Unsafe YAML load', severity: 'medium', category: 'deser', args: [0] };
  }

  // ---- path traversal
  if (canonical) {
    const parts = canonical.split('.');
    const mod = parts[0];
    const m = parts[parts.length - 1];
    if (FS_MODULES.has(mod) && FS_PATH_METHODS.has(m)) {
      const twoPaths = /^(copyFile|rename)/.test(m);
      return { rule_id: 'rp.path.fs', cwe: 'CWE-22', title: 'Path traversal in file system access', severity: 'high', category: 'path', args: twoPaths ? [0, 1] : [0] };
    }
  }
  if (chain && chain.length === 2 && RESPONSE_ROOTS.has(root) && (method === 'sendFile' || method === 'download' || method === 'attachment')) {
    return { rule_id: 'rp.path.send-file', cwe: 'CWE-22', title: 'Path traversal in file download', severity: 'high', category: 'path', args: [0] };
  }

  // ---- SSRF
  if (canonical) {
    const parts = canonical.split('.');
    const mod = parts[0];
    const m = parts.length > 1 ? parts.slice(1).join('.') : '';
    if (HTTP_CLIENTS[mod] && HTTP_CLIENTS[mod].has(m)) {
      return { rule_id: 'rp.ssrf.http-client', cwe: 'CWE-918', title: 'Server-side request forgery', severity: 'high', category: 'ssrf', args: [0], objectKey: 'url' };
    }
  }
  if (raw === 'fetch' && canonical === 'fetch') {
    return { rule_id: 'rp.ssrf.fetch', cwe: 'CWE-918', title: 'Server-side request forgery', severity: 'high', category: 'ssrf', args: [0] };
  }

  // ---- open redirect
  if (chain && chain.length === 2 && RESPONSE_ROOTS.has(root) && method === 'redirect' && nargs > 0) {
    return { rule_id: 'rp.redirect.open', cwe: 'CWE-601', title: 'Open redirect', severity: 'medium', category: 'redirect', args: [nargs - 1] };
  }

  // ---- XSS
  if (chain && chain.length === 2 && RESPONSE_ROOTS.has(root) && root !== 'ctx' && (method === 'send' || method === 'write' || method === 'end') && nargs > 0) {
    return { rule_id: 'rp.xss.response', cwe: 'CWE-79', title: 'Reflected cross-site scripting', severity: 'medium', category: 'xss', args: [0], requireUserOrHtml: true };
  }
  if (raw === 'document.write' || raw === 'document.writeln') {
    return { rule_id: 'rp.xss.document-write', cwe: 'CWE-79', title: 'DOM cross-site scripting (document.write)', severity: 'high', category: 'xss', args: 'all' };
  }
  if (method === 'insertAdjacentHTML' && nargs > 1) {
    return { rule_id: 'rp.xss.insert-html', cwe: 'CWE-79', title: 'DOM cross-site scripting', severity: 'high', category: 'xss', args: [1] };
  }

  // ---- SQL injection (query execution)
  if (chain && chain.length >= 2 && SQL_METHODS.has(method) && !REQUEST_ROOTS.has(root) && !(canonical || '').startsWith('child_process')) {
    return { rule_id: 'rp.sqli.query', cwe: 'CWE-89', title: 'SQL injection', severity: 'high', category: 'sqli', args: [0] };
  }

  // ---- NoSQL injection
  if (chain && chain.length >= 2 && NOSQL_METHODS.has(method) && !REQUEST_ROOTS.has(root)) {
    return { rule_id: 'rp.nosqli.query-object', cwe: 'CWE-943', title: 'NoSQL injection (query object from request)', severity: 'medium', category: 'nosqli', args: [0], requireUser: true, requireDirectObject: true };
  }

  // ---- ReDoS
  if ((raw === 'RegExp') && nargs > 0) {
    return { rule_id: 'rp.redos.dynamic-regex', cwe: 'CWE-1333', title: 'Regular expression built from input (ReDoS)', severity: 'medium', category: 'redos', args: [0] };
  }

  return null;
}

// SQL / HTML string construction (no explicit sink required)
const SQL_TEXT = /\b(SELECT\b[\s\S]*\bFROM|INSERT\s+INTO|UPDATE\b[\s\S]*\bSET|DELETE\s+FROM|DROP\s+(TABLE|DATABASE)|CREATE\s+TABLE|ALTER\s+TABLE)\b/i;
const SQL_FRAGMENT = /\b(WHERE|AND|OR|VALUES|ORDER\s+BY|LIMIT|LIKE)\b[\s\S]*[=<>'"(%]?\s*$/i;
const HTML_TEXT = /<\/?[a-zA-Z][a-zA-Z0-9-]*(\s[^<>]*)?>|<[a-zA-Z][a-zA-Z0-9-]*\s/;

const SECRET_NAME = /^(pass(word|wd)?|pwd|secret|client_?secret|api_?key|apikey|access_?key|private_?key|auth_?token|token|jwt_?secret|session_?secret|db_?pass(word)?)$/i;
const PLACEHOLDER = /^(changeme|change_me|password|secret|xxx+|\*+|todo|example|your[_-].*|<.*>|test|dummy)$/i;

module.exports = {
  isSourceChain, isSourceCall, sourceLabel, getterLabel, isSanitizer, NEUTRAL_PROPS, matchCallSink,
  SQL_TEXT, SQL_FRAGMENT, HTML_TEXT, EVIL_REGEX, SECRET_NAME, PLACEHOLDER, SEVERITY_RANK, RESPONSE_ROOTS,
};
