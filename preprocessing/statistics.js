/**
 * statistics.js
 * ReachPrioritizer Phase 1 — Step 10
 *
 * Generates comprehensive dataset statistics from the processed data.
 * Produces:
 *   reports/dataset_statistics.json
 *   reports/dataset_statistics.md
 *
 * SAFETY: Read-only on processed data.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Paths ────────────────────────────────────────────────────────────────────
const ROOT        = path.resolve(__dirname, '..');
const CLEAN       = path.join(ROOT, 'data', 'processed', 'jsvul_clean.jsonl');
const SPLITS_DIR  = path.join(ROOT, 'data', 'processed', 'splits');
const MANIFEST    = path.join(ROOT, 'data', 'processed', 'split_manifest.json');
const REPORTS_DIR = path.join(ROOT, 'reports');

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

function loadJsonl(fp) {
  if (!fs.existsSync(fp)) return [];
  return fs.readFileSync(fp, 'utf8')
    .split('\n')
    .filter(l => l.trim())
    .map(l => { try { return JSON.parse(l); } catch (_) { return null; } })
    .filter(Boolean);
}

function percentile(arr, p) {
  if (!arr.length) return null;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.floor((p / 100) * sorted.length);
  return sorted[Math.min(idx, sorted.length - 1)];
}

function mean(arr) {
  if (!arr.length) return null;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function median(arr) { return percentile(arr, 50); }

function topN(countMap, n) {
  return Object.entries(countMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, v]) => ({ key: k, count: v }));
}

// ── Load records ─────────────────────────────────────────────────────────────
console.log('[statistics] Loading records...');
const records = loadJsonl(CLEAN);
console.log(`[statistics] ${records.length} total records.`);

const trainRecs = loadJsonl(path.join(SPLITS_DIR, 'train.jsonl'));
const valRecs   = loadJsonl(path.join(SPLITS_DIR, 'validation.jsonl'));
const testRecs  = loadJsonl(path.join(SPLITS_DIR, 'test.jsonl'));

const manifest = fs.existsSync(MANIFEST)
  ? JSON.parse(fs.readFileSync(MANIFEST, 'utf8'))
  : null;

// ── Aggregate statistics ──────────────────────────────────────────────────────

// Label distribution
let vulnCount  = 0, benignCount = 0;
let parseSucc  = 0, parseFail   = 0, parseNull = 0;
let rawDups    = 0, normDups    = 0;

// Distributions
const sourceLengths = [];
const lineCounts    = [];
const cweMap        = {};
const cveMap        = {};
const repoMap       = {};
const projectMap    = {};
const nodeTypeMap   = {};

for (const r of records) {
  if (r.label === 1) vulnCount++; else benignCount++;
  if (r.parse_success === true)  parseSucc++;
  else if (r.parse_success === false) parseFail++;
  else parseNull++;

  if (r.is_raw_duplicate)  rawDups++;
  if (r.is_norm_duplicate) normDups++;

  if (r.source_length > 0) sourceLengths.push(r.source_length);
  if (r.line_count > 0)    lineCounts.push(r.line_count);

  // CWE
  for (const c of (r.cwe || [])) { cweMap[c] = (cweMap[c] || 0) + 1; }
  // CVE
  for (const c of (r.cve || [])) { cveMap[c] = (cveMap[c] || 0) + 1; }

  const repo = `${r.organisation}/${r.project}`;
  repoMap[repo] = (repoMap[repo] || 0) + 1;

  if (r.node_type) nodeTypeMap[r.node_type] = (nodeTypeMap[r.node_type] || 0) + 1;
}

// Samples per repo
const samplesPerRepo = Object.values(repoMap);
const topRepos = topN(repoMap, 20);
const topCWEs  = topN(cweMap, 20);
const topCVEs  = topN(cveMap, 10);
const topNodeTypes = topN(nodeTypeMap, 10);

function splitLabelDist(recs) {
  let v = 0, b = 0;
  for (const r of recs) r.label === 1 ? v++ : b++;
  return { total: recs.length, vulnerable: v, benign: b, vuln_pct: recs.length > 0 ? (v/recs.length*100).toFixed(1) : 'N/A' };
}

const stats = {
  generated_at:     new Date().toISOString(),
  total_samples:    records.length,
  label_dist: {
    vulnerable:     vulnCount,
    benign:         benignCount,
    vuln_fraction:  records.length > 0 ? vulnCount / records.length : null,
  },
  parse_stats: {
    success:        parseSucc,
    failure:        parseFail,
    no_source:      parseNull,
    success_rate:   (parseSucc + parseFail) > 0 ? parseSucc / (parseSucc + parseFail) : null,
  },
  duplicate_stats: {
    raw_duplicate_records:  rawDups,
    norm_duplicate_records: normDups,
  },
  source_length_dist: {
    min:    sourceLengths.length > 0 ? Math.min(...sourceLengths) : null,
    max:    sourceLengths.length > 0 ? Math.max(...sourceLengths) : null,
    mean:   mean(sourceLengths),
    median: median(sourceLengths),
    p25:    percentile(sourceLengths, 25),
    p75:    percentile(sourceLengths, 75),
    p95:    percentile(sourceLengths, 95),
  },
  line_count_dist: {
    min:    lineCounts.length > 0 ? Math.min(...lineCounts) : null,
    max:    lineCounts.length > 0 ? Math.max(...lineCounts) : null,
    mean:   mean(lineCounts),
    median: median(lineCounts),
    p25:    percentile(lineCounts, 25),
    p75:    percentile(lineCounts, 75),
    p95:    percentile(lineCounts, 95),
  },
  repository_count: Object.keys(repoMap).length,
  samples_per_repo: {
    min:    samplesPerRepo.length > 0 ? Math.min(...samplesPerRepo) : null,
    max:    samplesPerRepo.length > 0 ? Math.max(...samplesPerRepo) : null,
    mean:   mean(samplesPerRepo),
    median: median(samplesPerRepo),
  },
  top_repositories: topRepos,
  cwe_distribution:  topCWEs,
  cve_distribution:  topCVEs,
  node_type_distribution: topNodeTypes,
  unique_cwes: Object.keys(cweMap).length,
  unique_cves: Object.keys(cveMap).length,
  splits: {
    train:      splitLabelDist(trainRecs),
    validation: splitLabelDist(valRecs),
    test:       splitLabelDist(testRecs),
    train_repos: manifest ? manifest.splits.train.repositories : null,
    val_repos:   manifest ? manifest.splits.validation.repositories : null,
    test_repos:  manifest ? manifest.splits.test.repositories : null,
  },
};

// ── Write JSON report ─────────────────────────────────────────────────────────
ensureDir(REPORTS_DIR);
fs.writeFileSync(
  path.join(REPORTS_DIR, 'dataset_statistics.json'),
  JSON.stringify(stats, null, 2),
  'utf8'
);

// ── Write Markdown report ─────────────────────────────────────────────────────
function fmt(n) { return n !== null && n !== undefined ? n.toFixed ? n.toFixed(1) : String(n) : 'N/A'; }
function fmtI(n) { return n !== null && n !== undefined ? String(Math.round(n)) : 'N/A'; }

const cweRows = topCWEs.map(x => `| ${x.key} | ${x.count} |`).join('\n');
const repoRows = topRepos.map(x => `| ${x.key} | ${x.count} |`).join('\n');
const ntRows   = topNodeTypes.map(x => `| ${x.key} | ${x.count} |`).join('\n');

const md = `# Dataset Statistics Report

> Generated: ${stats.generated_at}
> Dataset: JsVul 08_final (processed)

---

## 1. Overall Sample Counts

| Metric | Count |
|--------|-------|
| Total usable samples | ${stats.total_samples} |
| Vulnerable samples | ${stats.label_dist.vulnerable} |
| Benign samples | ${stats.label_dist.benign} |
| Vulnerable fraction | ${(stats.label_dist.vuln_fraction * 100).toFixed(2)}% |
| Unique repositories | ${stats.repository_count} |
| Unique CWEs | ${stats.unique_cwes} |
| Unique CVEs | ${stats.unique_cves} |

## 2. Class Balance

| Label | Count | Percentage |
|-------|-------|-----------|
| Vulnerable (label=1) | ${stats.label_dist.vulnerable} | ${(stats.label_dist.vuln_fraction * 100).toFixed(2)}% |
| Benign (label=0) | ${stats.label_dist.benign} | ${(100 - stats.label_dist.vuln_fraction * 100).toFixed(2)}% |

> **Note**: Class imbalance should be accounted for in model training (e.g. weighted loss, oversampling).

## 3. Parse Statistics

| Metric | Count |
|--------|-------|
| Parse success | ${stats.parse_stats.success} |
| Parse failure | ${stats.parse_stats.failure} |
| No source (skipped) | ${stats.parse_stats.no_source} |
| Parse success rate | ${stats.parse_stats.success_rate !== null ? (stats.parse_stats.success_rate * 100).toFixed(2) + '%' : 'N/A'} |

## 4. Duplicate Statistics

| Metric | Count |
|--------|-------|
| Raw-exact duplicate records | ${stats.duplicate_stats.raw_duplicate_records} |
| Normalized duplicate records | ${stats.duplicate_stats.norm_duplicate_records} |

## 5. Source Code Length Distribution (characters)

| Percentile | Value |
|-----------|-------|
| Min | ${fmtI(stats.source_length_dist.min)} |
| P25 | ${fmtI(stats.source_length_dist.p25)} |
| Median | ${fmtI(stats.source_length_dist.median)} |
| Mean | ${fmtI(stats.source_length_dist.mean)} |
| P75 | ${fmtI(stats.source_length_dist.p75)} |
| P95 | ${fmtI(stats.source_length_dist.p95)} |
| Max | ${fmtI(stats.source_length_dist.max)} |

## 6. Function Line Count Distribution

| Percentile | Value |
|-----------|-------|
| Min | ${fmtI(stats.line_count_dist.min)} |
| P25 | ${fmtI(stats.line_count_dist.p25)} |
| Median | ${fmtI(stats.line_count_dist.median)} |
| Mean | ${fmtI(stats.line_count_dist.mean)} |
| P75 | ${fmtI(stats.line_count_dist.p75)} |
| P95 | ${fmtI(stats.line_count_dist.p95)} |
| Max | ${fmtI(stats.line_count_dist.max)} |

## 7. Samples per Repository

| Metric | Value |
|--------|-------|
| Min | ${fmtI(stats.samples_per_repo.min)} |
| Median | ${fmtI(stats.samples_per_repo.median)} |
| Mean | ${fmtI(stats.samples_per_repo.mean)} |
| Max | ${fmtI(stats.samples_per_repo.max)} |

## 8. CWE Distribution (top 20)

| CWE | Count |
|-----|-------|
${cweRows || '| (none) | 0 |'}

## 9. Train / Validation / Test Split

| Split | Records | Repositories | Vulnerable | Benign | Vuln% |
|-------|---------|-------------|-----------|--------|-------|
| Train | ${stats.splits.train.total} | ${stats.splits.train_repos ?? 'N/A'} | ${stats.splits.train.vulnerable} | ${stats.splits.train.benign} | ${stats.splits.train.vuln_pct}% |
| Validation | ${stats.splits.validation.total} | ${stats.splits.val_repos ?? 'N/A'} | ${stats.splits.validation.vulnerable} | ${stats.splits.validation.benign} | ${stats.splits.validation.vuln_pct}% |
| Test | ${stats.splits.test.total} | ${stats.splits.test_repos ?? 'N/A'} | ${stats.splits.test.vulnerable} | ${stats.splits.test.benign} | ${stats.splits.test.vuln_pct}% |

## 10. Top 20 Repositories by Sample Count

| Repository | Samples |
|------------|---------|
${repoRows}

## 11. AST Node Type Distribution

| Node Type | Count |
|-----------|-------|
${ntRows}

---

*End of Dataset Statistics Report*
`;

fs.writeFileSync(path.join(REPORTS_DIR, 'dataset_statistics.md'), md, 'utf8');

console.log(`\n[statistics] ====== STATISTICS SUMMARY ======`);
console.log(`  Total samples:      ${stats.total_samples}`);
console.log(`  Vulnerable:         ${stats.label_dist.vulnerable}`);
console.log(`  Benign:             ${stats.label_dist.benign}`);
console.log(`  Parse success rate: ${stats.parse_stats.success_rate !== null ? (stats.parse_stats.success_rate * 100).toFixed(1) + '%' : 'N/A'}`);
console.log(`  Unique CWEs:        ${stats.unique_cwes}`);
console.log(`  Unique CVEs:        ${stats.unique_cves}`);
console.log('[statistics] Reports written to reports/dataset_statistics.{json,md}');

module.exports = { stats };
