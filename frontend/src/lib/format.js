/** Presentation helpers shared by all pages. */

export const RISK = {
  Critical: { color: '#FF4D5E', text: 'text-risk-critical', bg: 'bg-risk-critical/10', border: 'border-risk-critical/40' },
  High: { color: '#FF9442', text: 'text-risk-high', bg: 'bg-risk-high/10', border: 'border-risk-high/40' },
  Medium: { color: '#FFD54A', text: 'text-risk-medium', bg: 'bg-risk-medium/10', border: 'border-risk-medium/40' },
  Low: { color: '#7FA0B8', text: 'text-risk-low', bg: 'bg-risk-low/10', border: 'border-risk-low/40' },
}
export const RISK_ORDER = ['Critical', 'High', 'Medium', 'Low']

export const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

export const REACH = {
  reachable: { label: 'Reachable', hint: 'Reachable from an active route / request handler', tone: 'danger' },
  startup_only: { label: 'Startup only', hint: 'Runs only while the app boots — not driven by requests', tone: 'warn' },
  unreachable: { label: 'Dead code', hint: 'No path from any entry point', tone: 'muted' },
  unknown: { label: 'Unknown', hint: 'Could not be placed in the call graph', tone: 'muted' },
}

export const TAINT = {
  user_input: { label: 'User input', hint: 'Attacker-controlled data proven to reach the sink', tone: 'danger' },
  parameter: { label: 'Parameter', hint: 'A function parameter reaches the sink; no caller passes user input', tone: 'warn' },
  none: { label: 'No data flow', hint: 'Configuration / code issue without a data flow', tone: 'muted' },
  unknown: { label: 'AI only', hint: 'Flagged by the AI model, no rule matched', tone: 'muted' },
}

export function riskOf(score) {
  if (score >= 70) return 'Critical'
  if (score >= 45) return 'High'
  if (score >= 25) return 'Medium'
  return 'Low'
}

/** 'src/a.js::Class.method#L12' -> 'Class.method' */
export function fnName(id) {
  if (!id) return ''
  const name = id.includes('::') ? id.split('::').slice(1).join('::') : id
  return name.replace(/#L\d+(:\d+)?$/, '')
}

export function fileOf(id) {
  return id && id.includes('::') ? id.split('::')[0] : ''
}

export function prettyFn(name) {
  if (!name) return 'anonymous'
  if (name === '__top_level__') return 'module top-level'
  return name.replace(/:L\d+>$/, '>')
}

export function timeAgo(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const s = Math.round((Date.now() - d.getTime()) / 1000)
  if (s < 45) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  if (s < 86400 * 7) return `${Math.round(s / 86400)} d ago`
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

export function duration(ms) {
  if (ms == null) return '–'
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

export function pct(v, digits = 0) {
  if (v == null || Number.isNaN(v)) return '–'
  return `${(v * 100).toFixed(digits)}%`
}

export function bytes(n) {
  if (!n) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)))
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`
}

export const CWE_INFO = {
  'CWE-78': { name: 'OS Command Injection', fix: 'Never build shell commands from input. Use execFile/spawn with an argument array (no shell) and an allowlist of permitted values.' },
  'CWE-89': { name: 'SQL Injection', fix: 'Use parameterized queries / prepared statements (placeholders like ? or $1) or a query builder. Never concatenate input into SQL text.' },
  'CWE-94': { name: 'Code Injection', fix: 'Remove eval / new Function / vm on input. Parse data with JSON.parse or a dedicated, safe parser.' },
  'CWE-22': { name: 'Path Traversal', fix: 'Resolve the path against a fixed base directory and verify the result still starts with that directory, or use path.basename for file names.' },
  'CWE-918': { name: 'Server-Side Request Forgery', fix: 'Validate destination URLs against an allowlist of hosts and schemes; block internal address ranges.' },
  'CWE-79': { name: 'Cross-Site Scripting', fix: 'Encode output for the HTML context (or use a templating engine with auto-escaping); sanitize rich HTML with DOMPurify.' },
  'CWE-601': { name: 'Open Redirect', fix: 'Only redirect to relative paths or to an allowlist of trusted URLs.' },
  'CWE-1321': { name: 'Prototype Pollution', fix: 'Block __proto__, constructor and prototype keys, use Object.create(null) maps, or a hardened merge utility.' },
  'CWE-502': { name: 'Insecure Deserialization', fix: 'Do not deserialize untrusted data with libraries that can execute code; use JSON and validate the schema.' },
  'CWE-611': { name: 'XML External Entities', fix: 'Disable external entity expansion (noent: false) and DTD loading in the XML parser.' },
  'CWE-943': { name: 'NoSQL Injection', fix: 'Validate types (reject objects where strings are expected), avoid $where, and sanitize operators (e.g. mongo-sanitize).' },
  'CWE-1333': { name: 'Regular Expression DoS', fix: 'Avoid nested quantifiers, bound input length, or use a linear-time regex engine (re2).' },
  'CWE-798': { name: 'Hardcoded Credentials', fix: 'Load secrets from environment variables or a secrets manager and rotate the exposed value.' },
  'CWE-327': { name: 'Weak Cryptography', fix: 'Use SHA-256+ for hashing, bcrypt/argon2 for passwords, and modern AEAD ciphers with random IVs.' },
  'CWE-295': { name: 'Improper Certificate Validation', fix: 'Keep TLS verification enabled; trust a custom CA instead of disabling checks.' },
}

export function cweName(cwe) {
  return (CWE_INFO[cwe] && CWE_INFO[cwe].name) || (cwe === 'CWE-Unknown' ? 'AI suspicion' : cwe)
}
