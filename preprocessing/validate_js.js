/**
 * validate_js.js
 * ReachPrioritizer Phase 1 — Step 3
 *
 * Validates JavaScript source code from jsvul_normalized.jsonl using @babel/parser.
 * Produces:
 *   reports/javascript_validation_report.json
 *   reports/javascript_validation_report.md
 *
 * SAFETY: Only parses; never executes code.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { parse } = require('@babel/parser');

// ── Paths ────────────────────────────────────────────────────────────────────
const ROOT         = path.resolve(__dirname, '..');
const NORMALIZED   = path.join(ROOT, 'data', 'processed', 'jsvul_normalized.jsonl');
const REPORTS_DIR  = path.join(ROOT, 'reports');

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ── Babel parser options ─────────────────────────────────────────────────────
// Support modern ECMAScript. JSX is included because some Node.js projects
// (e.g. React-based backends) may have JSX in function bodies.
// We allow errors so we can collect them rather than throw on first failure.
const BABEL_OPTS = {
  sourceType: 'unambiguous',  // auto-detect module vs script
  allowImportExportEverywhere: true,
  allowReturnOutsideFunction: true,  // function bodies extracted from context
  allowSuperOutsideMethod: true,
  allowUndeclaredExports: true,
  strictMode: false,
  errorRecovery: false,
  plugins: [
    'jsx',
    'typescript',           // allow TS syntax silently
    'decorators-legacy',
    'classProperties',
    'classStaticBlock',
    'dynamicImport',
    'exportDefaultFrom',
    'exportNamespaceFrom',
    'nullishCoalescingOperator',
    'optionalChaining',
    'topLevelAwait',
    'bigInt',
    'logicalAssignment',
    'numericSeparator',
    'privateIn',
  ],
};

function tryParse(src) {
  // Attempt 1: wrap in function to handle bare function bodies
  // that aren't full programs
  const attempts = [
    src,
    `(${src})`,
    `async function __wrapper__() { ${src} }`,
    `class __C__ { ${src} }`,
  ];

  for (const attempt of attempts) {
    try {
      parse(attempt, BABEL_OPTS);
      return { success: true, error: null };
    } catch (_) {
      // try next strategy
    }
  }

  // Final attempt: capture error message from raw parse
  try {
    parse(src, BABEL_OPTS);
    return { success: true, error: null };
  } catch (e) {
    return { success: false, error: e.message || String(e) };
  }
}

// ── Process records ──────────────────────────────────────────────────────────
console.log('[validate_js] Reading normalized records...');

const lines = fs.readFileSync(NORMALIZED, 'utf8')
  .split('\n')
  .filter(l => l.trim().length > 0);

console.log(`[validate_js] ${lines.length} records to validate.`);

let total         = 0;
let withSource    = 0;
let noSource      = 0;
let parseSuccess  = 0;
let parseFailure  = 0;
const errorBuckets = {};  // error type → count
const failureSamples = []; // first 20 failures for reporting

// Updated records with validation fields
const validatedLines = [];

for (const line of lines) {
  let rec;
  try { rec = JSON.parse(line); }
  catch (_) { continue; }

  total++;

  const src = rec.original_source;
  if (!src || src.trim().length === 0) {
    noSource++;
    rec.parse_success = null;
    rec.parser_error  = null;
    rec.source_length = 0;
    rec.line_count    = 0;
    validatedLines.push(JSON.stringify(rec));
    continue;
  }

  withSource++;
  const result = tryParse(src);
  rec.parse_success = result.success;
  rec.parser_error  = result.error;
  rec.source_length = src.length;
  rec.line_count    = src.split('\n').length;

  if (result.success) {
    parseSuccess++;
  } else {
    parseFailure++;
    // Bucket errors by first word
    const bucket = (result.error || 'unknown').split(/[\s:(]/)[0] || 'unknown';
    errorBuckets[bucket] = (errorBuckets[bucket] || 0) + 1;
    if (failureSamples.length < 20) {
      failureSamples.push({
        sample_id:     rec.sample_id,
        organisation:  rec.organisation,
        project:       rec.project,
        function_name: rec.function_name,
        error:         result.error,
        source_preview: src.substring(0, 150).replace(/\n/g, ' '),
      });
    }
  }

  validatedLines.push(JSON.stringify(rec));

  if (total % 10000 === 0) {
    console.log(`[validate_js]   Processed ${total}/${lines.length}...`);
  }
}

// Write back validated JSONL (overwrite normalized with parse fields added)
fs.writeFileSync(NORMALIZED, validatedLines.join('\n') + '\n', 'utf8');
console.log('[validate_js] Validation fields merged back into jsvul_normalized.jsonl');

// ── Reports ──────────────────────────────────────────────────────────────────
const jsonReport = {
  timestamp:     new Date().toISOString(),
  total_records: total,
  with_source:   withSource,
  no_source:     noSource,
  parse_success: parseSuccess,
  parse_failure: parseFailure,
  parse_success_rate: withSource > 0
    ? parseSuccess / withSource
    : null,
  error_buckets:    errorBuckets,
  failure_samples:  failureSamples,
};

ensureDir(REPORTS_DIR);
fs.writeFileSync(
  path.join(REPORTS_DIR, 'javascript_validation_report.json'),
  JSON.stringify(jsonReport, null, 2),
  'utf8'
);

const pct = (n, d) => d > 0 ? `${((n / d) * 100).toFixed(2)}%` : 'N/A';
const errorRows = Object.entries(errorBuckets)
  .sort((a, b) => b[1] - a[1])
  .map(([k, v]) => `| ${k} | ${v} |`)
  .join('\n');

const sampleRows = failureSamples.map((s, i) =>
  `### Failure ${i + 1}\n` +
  `- **Sample ID:** \`${s.sample_id}\`\n` +
  `- **Repo:** ${s.organisation}/${s.project}\n` +
  `- **Function:** \`${s.function_name}\`\n` +
  `- **Error:** ${s.error}\n` +
  `- **Preview:** \`${s.source_preview}\`\n`
).join('\n');

const md = `# JavaScript Validation Report

> Generated: ${jsonReport.timestamp}
> Parser: @babel/parser with modern ECMAScript plugin suite

---

## Summary

| Metric | Count | Percentage |
|--------|-------|-----------|
| Total records | ${total} | 100% |
| Records with source | ${withSource} | ${pct(withSource, total)} |
| Records without source | ${noSource} | ${pct(noSource, total)} |
| Parse successes | ${parseSuccess} | ${pct(parseSuccess, withSource)} of with-source |
| Parse failures | ${parseFailure} | ${pct(parseFailure, withSource)} of with-source |

## Parse Error Breakdown

| Error Type | Count |
|------------|-------|
${errorRows || '| (none) | 0 |'}

## Parse Failure Samples (first ${failureSamples.length})

${sampleRows || 'No failures.'}

---

## Notes

- Parse attempts used multiple strategies: raw, wrapped in parens, wrapped in async function, wrapped in class body.
- TypeScript syntax plugin enabled to handle \`.ts\` snippets present in some Node.js repositories.
- Failures are reported but NOT discarded here. The cleaning stage (Step 4) applies filtering policy.

---

*End of JavaScript Validation Report*
`;

fs.writeFileSync(path.join(REPORTS_DIR, 'javascript_validation_report.md'), md, 'utf8');

console.log(`\n[validate_js] ====== VALIDATION SUMMARY ======`);
console.log(`  Total records:    ${total}`);
console.log(`  With source:      ${withSource}`);
console.log(`  No source:        ${noSource}`);
console.log(`  Parse success:    ${parseSuccess} (${pct(parseSuccess, withSource)} of with-source)`);
console.log(`  Parse failure:    ${parseFailure} (${pct(parseFailure, withSource)} of with-source)`);
console.log('[validate_js] Reports written to reports/javascript_validation_report.{json,md}');

module.exports = { jsonReport };
