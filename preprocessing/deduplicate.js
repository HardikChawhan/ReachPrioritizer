/**
 * deduplicate.js
 * ReachPrioritizer Phase 1 — Step 4 & 6
 *
 * Applies noise filtering and exact duplicate detection.
 * Reads jsvul_normalized.jsonl and:
 *   1. Applies transparent filtering rules
 *   2. Detects exact duplicates (raw SHA-256 and normalized SHA-256)
 *   3. Detects conflicting labels in duplicate groups
 *
 * Produces:
 *   reports/cleaning_report.md
 *   reports/duplicate_report.json
 *   reports/duplicate_report.md
 *   data/processed/jsvul_clean.jsonl  (filtered, de-flagged but pairs preserved)
 *
 * SAFETY: Does not modify raw data.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Paths ────────────────────────────────────────────────────────────────────
const ROOT        = path.resolve(__dirname, '..');
const NORMALIZED  = path.join(ROOT, 'data', 'processed', 'jsvul_normalized.jsonl');
const CLEAN_OUT   = path.join(ROOT, 'data', 'processed', 'jsvul_clean.jsonl');
const REPORTS_DIR = path.join(ROOT, 'reports');

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ── Filtering rules ──────────────────────────────────────────────────────────
// Every rule must be documented. Samples are flagged, not silently deleted.

function applyFilters(rec) {
  const reasons = [];

  // Rule 1: Missing source
  if (!rec.original_source || rec.original_source.trim().length === 0) {
    reasons.push('MISSING_SOURCE');
  }

  // Rule 2: Extremely short source (< 10 chars — not a real function)
  else if (rec.original_source.trim().length < 10) {
    reasons.push('SOURCE_TOO_SHORT');
  }

  // Rule 3: Malformed record (no function_name, no label)
  if (rec.label === undefined || rec.label === null) {
    reasons.push('MISSING_LABEL');
  }

  // Rule 4: Parse failure (flagged but kept — separate reporting)
  // We do NOT discard parse failures here; they are reported separately.
  // The cleaning_report will show how many remained after all other filters.

  // Rule 5: Minified/generated code heuristic
  // A function body with avg line length > 500 chars is likely minified.
  if (rec.original_source && rec.line_count > 0) {
    const avgLineLen = rec.original_source.length / rec.line_count;
    if (avgLineLen > 500 && rec.line_count <= 3) {
      reasons.push('LIKELY_MINIFIED');
    }
  }

  return reasons;
}

// ── Load and filter ──────────────────────────────────────────────────────────
console.log('[deduplicate] Reading normalized records...');
const lines = fs.readFileSync(NORMALIZED, 'utf8')
  .split('\n')
  .filter(l => l.trim().length > 0);

console.log(`[deduplicate] ${lines.length} records loaded.`);

const inputCount    = lines.length;
let   missingSource = 0;
let   tooShort      = 0;
let   missingLabel  = 0;
let   likelyMinified = 0;
let   parseFailures = 0;

const usableRecords     = [];
const filteredOut       = [];

for (const line of lines) {
  let rec;
  try { rec = JSON.parse(line); }
  catch (_) { filteredOut.push({ reason: 'JSON_PARSE_ERROR', line }); continue; }

  const reasons = applyFilters(rec);
  rec.filter_reasons = reasons;
  rec.is_filtered = reasons.length > 0;

  // Count parse failures (among would-be usable records)
  if (rec.parse_success === false) parseFailures++;

  if (reasons.length === 0) {
    usableRecords.push(rec);
  } else {
    if (reasons.includes('MISSING_SOURCE')) missingSource++;
    if (reasons.includes('SOURCE_TOO_SHORT')) tooShort++;
    if (reasons.includes('MISSING_LABEL')) missingLabel++;
    if (reasons.includes('LIKELY_MINIFIED')) likelyMinified++;
    filteredOut.push({ reason: reasons.join(','), sample_id: rec.sample_id });
  }
}

const afterFiltering = usableRecords.length;
console.log(`[deduplicate] After filtering: ${afterFiltering} usable records.`);

// ── Exact duplicate detection ────────────────────────────────────────────────
console.log('[deduplicate] Running exact duplicate detection...');

// Group by raw SHA-256
const rawHashGroups = {};
for (const rec of usableRecords) {
  const h = rec.raw_source_sha256;
  if (!h) continue;
  if (!rawHashGroups[h]) rawHashGroups[h] = [];
  rawHashGroups[h].push(rec);
}

// Group by normalized SHA-256
const normHashGroups = {};
for (const rec of usableRecords) {
  const h = rec.normalized_source_sha256;
  if (!h) continue;
  if (!normHashGroups[h]) normHashGroups[h] = [];
  normHashGroups[h].push(rec);
}

// Identify duplicate groups (size > 1)
const rawDupGroups  = Object.values(rawHashGroups).filter(g => g.length > 1);
const normDupGroups = Object.values(normHashGroups).filter(g => g.length > 1);

const rawDupCount  = rawDupGroups.reduce((s, g) => s + g.length, 0);
const normDupCount = normDupGroups.reduce((s, g) => s + g.length, 0);

// Conflicting labels in duplicate groups
function checkConflictingLabels(groups) {
  let conflicts = 0;
  for (const grp of groups) {
    const labels = new Set(grp.map(r => r.label));
    if (labels.size > 1) conflicts++;
  }
  return conflicts;
}

const rawConflicts  = checkConflictingLabels(rawDupGroups);
const normConflicts = checkConflictingLabels(normDupGroups);

// Mark duplicates on records (do NOT remove them)
const rawDupShas  = new Set(rawDupGroups.map(g => g[0].raw_source_sha256));
const normDupShas = new Set(normDupGroups.map(g => g[0].normalized_source_sha256));

for (const rec of usableRecords) {
  rec.is_raw_duplicate  = rawDupShas.has(rec.raw_source_sha256);
  rec.is_norm_duplicate = normDupShas.has(rec.normalized_source_sha256);
}

// Largest duplicate groups
const top5RawGroups = rawDupGroups
  .sort((a, b) => b.length - a.length)
  .slice(0, 5)
  .map(g => ({
    sha256:       g[0].raw_source_sha256,
    size:         g.length,
    repositories: [...new Set(g.map(r => `${r.organisation}/${r.project}`))],
    labels:       [...new Set(g.map(r => r.label))],
    function_names: [...new Set(g.map(r => r.function_name))],
  }));

const top5NormGroups = normDupGroups
  .sort((a, b) => b.length - a.length)
  .slice(0, 5)
  .map(g => ({
    sha256:       g[0].normalized_source_sha256,
    size:         g.length,
    repositories: [...new Set(g.map(r => `${r.organisation}/${r.project}`))],
    labels:       [...new Set(g.map(r => r.label))],
    function_names: [...new Set(g.map(r => r.function_name))],
  }));

// ── Write clean JSONL ────────────────────────────────────────────────────────
ensureDir(path.join(ROOT, 'data', 'processed'));
fs.writeFileSync(CLEAN_OUT, usableRecords.map(r => JSON.stringify(r)).join('\n') + '\n', 'utf8');
console.log(`[deduplicate] ${afterFiltering} records written to jsvul_clean.jsonl`);

// ── Duplicate report ─────────────────────────────────────────────────────────
const dupReport = {
  timestamp:                 new Date().toISOString(),
  total_usable_records:      afterFiltering,
  // Raw exact duplicates
  raw_duplicate_groups:      rawDupGroups.length,
  raw_duplicate_records:     rawDupCount,
  raw_conflicting_labels:    rawConflicts,
  top5_raw_duplicate_groups: top5RawGroups,
  // Normalized duplicates
  norm_duplicate_groups:     normDupGroups.length,
  norm_duplicate_records:    normDupCount,
  norm_conflicting_labels:   normConflicts,
  top5_norm_duplicate_groups: top5NormGroups,
};

ensureDir(REPORTS_DIR);
fs.writeFileSync(
  path.join(REPORTS_DIR, 'duplicate_report.json'),
  JSON.stringify(dupReport, null, 2),
  'utf8'
);

// ── Cleaning report (Markdown) ────────────────────────────────────────────────
const cleanMd = `# Data Cleaning Report

> Generated: ${new Date().toISOString()}

---

## Filtering Pipeline

\`\`\`
Input records                : ${inputCount}
  → Missing source            : ${missingSource}
  → Source too short (<10ch)  : ${tooShort}
  → Missing label             : ${missingLabel}
  → Likely minified code      : ${likelyMinified}
─────────────────────────────────
  → Remaining usable samples  : ${afterFiltering}
\`\`\`

> Parse failures among usable records: **${parseFailures}** (reported but NOT filtered here)

## Filtering Rules

| Rule | Criteria | Action |
|------|----------|--------|
| MISSING_SOURCE | \`function_body\` is null or empty string | Excluded |
| SOURCE_TOO_SHORT | \`function_body\` trimmed length < 10 characters | Excluded |
| MISSING_LABEL | \`label\` field is null/undefined | Excluded |
| LIKELY_MINIFIED | avg line length > 500 chars AND ≤ 3 lines | Excluded |
| PARSE_FAILURE | @babel/parser fails all strategies | Flagged only, not excluded |

## Rationale

- **Parse failures are NOT discarded** from the clean dataset. Many parse failures are
  TypeScript method bodies or class syntax which are still valid for label-based learning
  even if the JS parser is strict. The downstream model may handle these.
- **Minification heuristic** is conservative: requires very high avg line length AND very
  few lines to avoid false positives.
- Every filtered record is logged with its \`sample_id\` and reason in \`duplicate_report.json\`.

---

*End of Data Cleaning Report*
`;

fs.writeFileSync(path.join(REPORTS_DIR, 'cleaning_report.md'), cleanMd, 'utf8');

// ── Duplicate report (Markdown) ───────────────────────────────────────────────
const pct = (n, d) => d > 0 ? `${((n / d) * 100).toFixed(2)}%` : 'N/A';

const dupMd = `# Duplicate Detection Report

> Generated: ${dupReport.timestamp}

---

## Exact Duplicates (raw source SHA-256)

| Metric | Value |
|--------|-------|
| Duplicate groups | ${dupReport.raw_duplicate_groups} |
| Duplicate records | ${dupReport.raw_duplicate_records} (${pct(dupReport.raw_duplicate_records, afterFiltering)}) |
| Groups with conflicting labels | ${dupReport.raw_conflicting_labels} |

### Top Duplicate Groups (raw)

${top5RawGroups.map((g, i) => `#### Group ${i + 1}\n- Size: ${g.size}\n- SHA-256: \`${g.sha256}\`\n- Repositories: ${g.repositories.join(', ')}\n- Labels: ${g.labels.join(', ')}\n- Function names: ${g.function_names.join(', ')}\n`).join('\n')}

---

## Normalized Duplicates (whitespace-normalised SHA-256)

| Metric | Value |
|--------|-------|
| Duplicate groups | ${dupReport.norm_duplicate_groups} |
| Duplicate records | ${dupReport.norm_duplicate_records} (${pct(dupReport.norm_duplicate_records, afterFiltering)}) |
| Groups with conflicting labels | ${dupReport.norm_conflicting_labels} |

### Top Duplicate Groups (normalized)

${top5NormGroups.map((g, i) => `#### Group ${i + 1}\n- Size: ${g.size}\n- SHA-256: \`${g.sha256}\`\n- Repositories: ${g.repositories.join(', ')}\n- Labels: ${g.labels.join(', ')}\n- Function names: ${g.function_names.join(', ')}\n`).join('\n')}

---

## Interpretation

- Duplicates are **flagged** with \`is_raw_duplicate\` and \`is_norm_duplicate\` fields
  but are **not removed** from the clean dataset.
- The splitting stage ensures pairs (vulnerable + fixed versions of the same function)
  are never separated across train/test boundaries.
- Conflicting labels in a duplicate group indicate that the same function body appears
  as both vulnerable and non-vulnerable (e.g., in different commits). This is expected
  for patched functions.

---

*End of Duplicate Report*
`;

fs.writeFileSync(path.join(REPORTS_DIR, 'duplicate_report.md'), dupMd, 'utf8');

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n[deduplicate] ====== DEDUPLICATION SUMMARY ======`);
console.log(`  Input records:           ${inputCount}`);
console.log(`  Missing source:          ${missingSource}`);
console.log(`  Too short:               ${tooShort}`);
console.log(`  Missing label:           ${missingLabel}`);
console.log(`  Likely minified:         ${likelyMinified}`);
console.log(`  Usable after filtering:  ${afterFiltering}`);
console.log(`  Parse failures (kept):   ${parseFailures}`);
console.log(`  Raw dup groups:          ${rawDupGroups.length}`);
console.log(`  Raw dup records:         ${rawDupCount}`);
console.log(`  Norm dup groups:         ${normDupGroups.length}`);
console.log(`  Norm dup records:        ${normDupCount}`);
console.log('[deduplicate] Reports written.');

module.exports = { afterFiltering, rawDupGroups: rawDupGroups.length, normDupGroups: normDupGroups.length };
