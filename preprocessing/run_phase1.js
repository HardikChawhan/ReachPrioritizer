/**
 * run_phase1.js
 * ReachPrioritizer Phase 1 — Master pipeline runner
 *
 * Executes the complete Phase 1 preprocessing pipeline in order:
 *   Step 0 — Schema inspection
 *   Step 1 — Dataset inventory
 *   Step 2 — Normalization / extraction
 *   Step 3 — JavaScript validation
 *   Step 4+6 — Noise filtering + duplicate detection
 *   Step 8 — Leakage analysis
 *   Step 9 — Repository-disjoint splitting
 *   Step 10 — Dataset statistics
 *
 * Usage: node preprocessing/run_phase1.js
 *        npm run phase1
 *
 * SAFETY: Never modifies raw data.
 */

'use strict';

const { execSync } = require('child_process');
const fs            = require('fs');
const path          = require('path');

const ROOT = path.resolve(__dirname, '..');

function run(label, scriptName, nodeOpts) {
  const scriptPath = path.join(__dirname, scriptName);
  console.log(`\n${'='.repeat(60)}`);
  console.log(`PHASE 1 — ${label}`);
  console.log(`${'='.repeat(60)}`);
  const start = Date.now();
  const cmd = nodeOpts
    ? `node ${nodeOpts} "${scriptPath}"`
    : `node "${scriptPath}"`;
  try {
    execSync(cmd, { stdio: 'inherit', cwd: ROOT });
  } catch (e) {
    console.error(`\n[run_phase1] FAILED: ${label}`);
    console.error(e.message || String(e));
    process.exit(1);
  }
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`[run_phase1] ✅ ${label} completed in ${elapsed}s`);
}

// ── Execute pipeline ──────────────────────────────────────────────────────────
const pipelineStart = Date.now();

console.log('\n╔══════════════════════════════════════════════════════════╗');
console.log('║  ReachPrioritizer — Phase 1 Dataset Preparation Pipeline ║');
console.log('╚══════════════════════════════════════════════════════════╝\n');

run('Step 0 — Schema Inspection',          'inspect_schema.js');
run('Step 1 — Dataset Inventory',          'inventory.js');
run('Step 2 — Normalization & Extraction', 'normalize.js');
run('Step 3 — JavaScript Validation',      'validate_js.js');
run('Step 4+6 — Filtering & Deduplication', 'deduplicate.js');
run('Step 8 — Leakage & Pair Analysis',    'leakage_check.js', '--max-old-space-size=512');
run('Step 9 — Dataset Splitting',          'split.js');
run('Step 10 — Dataset Statistics',        'statistics.js');

// ── Load final summary numbers ────────────────────────────────────────────────
function loadJsonl(fp) {
  if (!fs.existsSync(fp)) return [];
  return fs.readFileSync(fp, 'utf8')
    .split('\n').filter(l => l.trim())
    .map(l => { try { return JSON.parse(l); } catch (_) { return null; } })
    .filter(Boolean);
}

function loadJson(fp) {
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch (_) { return null; }
}

const inventory   = loadJson(path.join(ROOT, 'reports', 'dataset_inventory.json'));
const valReport   = loadJson(path.join(ROOT, 'reports', 'javascript_validation_report.json'));
const dupReport   = loadJson(path.join(ROOT, 'reports', 'duplicate_report.json'));
const statsReport = loadJson(path.join(ROOT, 'reports', 'dataset_statistics.json'));
const manifest    = loadJson(path.join(ROOT, 'data', 'processed', 'split_manifest.json'));

const trainRecs = loadJsonl(path.join(ROOT, 'data', 'processed', 'splits', 'train.jsonl'));
const valRecs   = loadJsonl(path.join(ROOT, 'data', 'processed', 'splits', 'validation.jsonl'));
const testRecs  = loadJsonl(path.join(ROOT, 'data', 'processed', 'splits', 'test.jsonl'));

const elapsed = ((Date.now() - pipelineStart) / 1000).toFixed(1);

// ── Final summary ─────────────────────────────────────────────────────────────
console.log('\n');
console.log('╔══════════════════════════════════════════════════════════╗');
console.log('║              PHASE 1 PIPELINE FINAL SUMMARY              ║');
console.log('╚══════════════════════════════════════════════════════════╝');
console.log('');
console.log(`  Dataset files scanned:     ${inventory ? inventory.totalJsonFiles : 'N/A'}`);
console.log(`  JSON records (functions):  ${inventory ? inventory.totalFunctionRecords : 'N/A'}`);
console.log(`  Valid records:             ${inventory ? inventory.validJsonFiles : 'N/A'} JSON files`);
console.log(`  Invalid records:           ${inventory ? inventory.invalidJsonFiles : 'N/A'}`);
console.log(`  Source-bearing records:    ${inventory ? inventory.sourceBearingRecords : 'N/A'}`);
console.log(`  Usable samples:            ${statsReport ? statsReport.total_samples : 'N/A'}`);
console.log(`  Vulnerable samples:        ${statsReport ? statsReport.label_dist.vulnerable : 'N/A'}`);
console.log(`  Non-vulnerable samples:    ${statsReport ? statsReport.label_dist.benign : 'N/A'}`);
console.log(`  Repositories:              ${statsReport ? statsReport.repository_count : 'N/A'}`);
console.log(`  Unique CWEs:               ${statsReport ? statsReport.unique_cwes : 'N/A'}`);
console.log(`  Unique CVEs:               ${statsReport ? statsReport.unique_cves : 'N/A'}`);
console.log(`  Parse success rate:        ${valReport && valReport.parse_success_rate !== null ? (valReport.parse_success_rate * 100).toFixed(1) + '%' : 'N/A'}`);
console.log(`  Parse failures (kept):     ${valReport ? valReport.parse_failure : 'N/A'}`);
console.log(`  Exact duplicates:          ${dupReport ? dupReport.raw_duplicate_records : 'N/A'}`);
console.log(`  Normalized duplicates:     ${dupReport ? dupReport.norm_duplicate_records : 'N/A'}`);
console.log(`  Train:                     ${trainRecs.length} samples`);
console.log(`  Validation:                ${valRecs.length} samples`);
console.log(`  Test:                      ${testRecs.length} samples`);
console.log(`  Split disjoint:            ${manifest && manifest.disjointness_checks.all_disjoint ? '✅ YES' : '❌ NO'}`);
console.log(`  Total pipeline time:       ${elapsed}s`);
console.log('');
console.log('  Artifacts produced:');
console.log('    data/processed/jsvul_normalized.jsonl');
console.log('    data/processed/jsvul_clean.jsonl');
console.log('    data/processed/splits/train.jsonl');
console.log('    data/processed/splits/validation.jsonl');
console.log('    data/processed/splits/test.jsonl');
console.log('    data/processed/split_manifest.json');
console.log('    reports/jsvul_schema_report.md');
console.log('    reports/dataset_inventory.{json,md}');
console.log('    reports/javascript_validation_report.{json,md}');
console.log('    reports/cleaning_report.md');
console.log('    reports/duplicate_report.{json,md}');
console.log('    reports/pair_integrity_report.md');
console.log('    reports/dataset_statistics.{json,md}');
console.log('');

// Verify disjointness one final time
if (manifest && !manifest.disjointness_checks.all_disjoint) {
  console.error('[run_phase1] CRITICAL: Split disjointness check FAILED. Pipeline INCOMPLETE.');
  process.exit(1);
}

console.log('Phase 1 preprocessing completed successfully.');
