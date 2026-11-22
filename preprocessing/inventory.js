/**
 * inventory.js
 * ReachPrioritizer Phase 1 — Step 1
 *
 * Recursively scans the JsVul dataset and produces:
 *   reports/dataset_inventory.json
 *   reports/dataset_inventory.md
 *
 * SAFETY: Read-only. Never modifies raw data.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Paths ────────────────────────────────────────────────────────────────────
const ROOT        = path.resolve(__dirname, '..');
const FUNCTIONS   = path.join(ROOT, 'data', 'raw', 'tools', 'jsvul', '08_final', 'functions');
const METADATA    = path.join(ROOT, 'data', 'raw', 'tools', 'jsvul', '08_final', 'metadata');
const REPORTS_DIR = path.join(ROOT, 'reports');

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

function safeJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (_) { return null; }
}

// ── Scan functions/ directory ────────────────────────────────────────────────
console.log('[inventory] Scanning functions/ directory...');

const stats = {
  scanTimestamp:          new Date().toISOString(),
  totalJsonFiles:         0,
  validJsonFiles:         0,
  invalidJsonFiles:       0,
  emptyFiles:             0,
  malformedRecords:       0,
  organisations:          new Set(),
  projects:               new Set(),
  commitPairs:            new Set(),   // org/project/sha
  vuln_json_files:        0,
  fix_json_files:         0,
  totalFunctionRecords:   0,
  sourceBearingRecords:   0,
  recordsMissingSource:   0,
  vulnerableRecords:      0,
  nonVulnerableRecords:   0,
  recordsWithCWE:         0,          // enriched from metadata
  recordsWithCVE:         0,          // enriched from metadata
  recordsWithCommit:      0,          // all have commit via path
  recordsWithFilePath:    0,
  recordsWithLineInfo:    0,
  invalidFileList:        [],
  emptyFileList:          [],
  // Metadata stats
  metadataFiles:          0,
  metadataCommitsTotal:   0,
  metadataCVECommits:     0,
  metadataCWECommits:     0,
  uniqueCVEs:             new Set(),
  uniqueCWEs:             new Set(),
};

// Load metadata first to enrich function records with CWE/CVE
console.log('[inventory] Loading metadata for CWE/CVE enrichment...');
const metadataMap = {};  // key: "org/project/sha" → { cve, cwe }

function walkMetadata(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkMetadata(full);
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      stats.metadataFiles++;
      const data = safeJson(full);
      if (!data) continue;
      // file path: metadata/<org>/<project>.json
      const rel    = path.relative(METADATA, full);
      const parts  = rel.replace(/\\/g, '/').split('/');
      const org    = parts[0];
      const project = parts[1].replace(/\.json$/, '');
      for (const sha of Object.keys(data)) {
        stats.metadataCommitsTotal++;
        const rec = data[sha];
        const hasCVE = Array.isArray(rec.cve) && rec.cve.length > 0;
        const hasCWE = Array.isArray(rec.cwe) && rec.cwe.length > 0;
        if (hasCVE) { stats.metadataCVECommits++; (rec.cve || []).forEach(c => stats.uniqueCVEs.add(c)); }
        if (hasCWE) { stats.metadataCWECommits++; (rec.cwe || []).forEach(c => stats.uniqueCWEs.add(c)); }
        const key = `${org}/${project}/${sha}`;
        metadataMap[key] = {
          cve: rec.cve || [],
          cwe: rec.cwe || [],
          vuln_sha:     rec.vuln_sha || null,
          publish_time: rec.publish_time || null,
          commit_msg:   rec.commit_msg || null,
          github:       rec.github || [],
          files:        rec.files  || [],
        };
      }
    }
  }
}
walkMetadata(METADATA);

// Walk functions/
function walkFunctions(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFunctions(full);
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      stats.totalJsonFiles++;

      const size = fs.statSync(full).size;
      if (size === 0) {
        stats.emptyFiles++;
        stats.invalidJsonFiles++;
        stats.emptyFileList.push(path.relative(FUNCTIONS, full));
        continue;
      }

      const data = safeJson(full);
      if (!data) {
        stats.invalidJsonFiles++;
        stats.invalidFileList.push(path.relative(FUNCTIONS, full));
        continue;
      }
      stats.validJsonFiles++;

      // Path anatomy: functions/<org>/<project>/<sha>/<vuln|fix>.json
      const rel    = path.relative(FUNCTIONS, full).replace(/\\/g, '/');
      const parts  = rel.split('/');
      const org    = parts[0];
      const project = parts[1];
      const sha    = parts[2];
      const fileType = parts[3]; // "vuln.json" or "fix.json"

      stats.organisations.add(org);
      stats.projects.add(`${org}/${project}`);
      stats.commitPairs.add(`${org}/${project}/${sha}`);

      if (fileType === 'vuln.json') stats.vuln_json_files++;
      else if (fileType === 'fix.json') stats.fix_json_files++;

      // Look up metadata
      const metaKey = `${org}/${project}/${sha}`;
      const meta    = metadataMap[metaKey] || null;
      const hasCVE  = meta && meta.cve.length > 0;
      const hasCWE  = meta && meta.cwe.length > 0;

      // Process function records
      if (typeof data !== 'object' || Array.isArray(data)) {
        stats.malformedRecords++;
        continue;
      }

      for (const fileKey of Object.keys(data)) {
        const functions = data[fileKey];
        if (!Array.isArray(functions)) { stats.malformedRecords++; continue; }

        for (const fn of functions) {
          stats.totalFunctionRecords++;
          stats.recordsWithCommit++;  // Always have commit via path
          stats.recordsWithFilePath++; // fileKey is the file path

          // Source code
          const hasSrc = typeof fn.function_body === 'string' && fn.function_body.trim().length > 0;
          if (hasSrc) stats.sourceBearingRecords++;
          else        stats.recordsMissingSource++;

          // Label
          const isVuln = fn.vuln === true;
          if (isVuln) stats.vulnerableRecords++;
          else        stats.nonVulnerableRecords++;

          // Line info
          if (typeof fn.start_line === 'number' && typeof fn.end_line === 'number') {
            stats.recordsWithLineInfo++;
          }

          // CWE / CVE (from metadata)
          if (hasCWE) stats.recordsWithCWE++;
          if (hasCVE) stats.recordsWithCVE++;
        }
      }
    }
  }
}

walkFunctions(FUNCTIONS);

// ── Serialise results ────────────────────────────────────────────────────────
const output = {
  scanTimestamp:          stats.scanTimestamp,
  totalJsonFiles:         stats.totalJsonFiles,
  validJsonFiles:         stats.validJsonFiles,
  invalidJsonFiles:       stats.invalidJsonFiles,
  emptyFiles:             stats.emptyFiles,
  malformedRecords:       stats.malformedRecords,
  organisations:          stats.organisations.size,
  projects:               stats.projects.size,
  commitPairs:            stats.commitPairs.size,
  vuln_json_files:        stats.vuln_json_files,
  fix_json_files:         stats.fix_json_files,
  totalFunctionRecords:   stats.totalFunctionRecords,
  sourceBearingRecords:   stats.sourceBearingRecords,
  recordsMissingSource:   stats.recordsMissingSource,
  vulnerableRecords:      stats.vulnerableRecords,
  nonVulnerableRecords:   stats.nonVulnerableRecords,
  recordsWithCWE:         stats.recordsWithCWE,
  recordsWithCVE:         stats.recordsWithCVE,
  recordsWithCommit:      stats.recordsWithCommit,
  recordsWithFilePath:    stats.recordsWithFilePath,
  recordsWithLineInfo:    stats.recordsWithLineInfo,
  metadataFiles:          stats.metadataFiles,
  metadataCommitsTotal:   stats.metadataCommitsTotal,
  metadataCVECommits:     stats.metadataCVECommits,
  metadataCWECommits:     stats.metadataCWECommits,
  uniqueCVECount:         stats.uniqueCVEs.size,
  uniqueCWECount:         stats.uniqueCWEs.size,
  invalidFileList:        stats.invalidFileList,
  emptyFileList:          stats.emptyFileList,
};

ensureDir(REPORTS_DIR);
fs.writeFileSync(
  path.join(REPORTS_DIR, 'dataset_inventory.json'),
  JSON.stringify(output, null, 2),
  'utf8'
);

// ── Markdown report ──────────────────────────────────────────────────────────
const pct = (n, d) => d > 0 ? `${((n / d) * 100).toFixed(1)}%` : 'N/A';

const md = `# Dataset Inventory Report

> Generated: ${output.scanTimestamp}
> Dataset: JsVul 08_final
> Language scope: JavaScript / Node.js only

---

## File-Level Statistics

| Metric | Count |
|--------|-------|
| Total JSON files scanned | ${output.totalJsonFiles} |
| Valid JSON files | ${output.validJsonFiles} |
| Invalid / malformed JSON files | ${output.invalidJsonFiles} |
| Empty files (0 bytes) | ${output.emptyFiles} |
| Malformed record structures | ${output.malformedRecords} |
| vuln.json files | ${output.vuln_json_files} |
| fix.json files | ${output.fix_json_files} |

## Organisational Structure

| Metric | Count |
|--------|-------|
| Organisations (top-level GitHub owners) | ${output.organisations} |
| Projects (org/repo) | ${output.projects} |
| Fix commit pairs (vuln+fix) | ${output.commitPairs} |

## Function Record Statistics

| Metric | Count | % of total |
|--------|-------|-----------|
| Total function records | ${output.totalFunctionRecords} | 100% |
| Source-bearing records | ${output.sourceBearingRecords} | ${pct(output.sourceBearingRecords, output.totalFunctionRecords)} |
| Records missing source | ${output.recordsMissingSource} | ${pct(output.recordsMissingSource, output.totalFunctionRecords)} |
| Vulnerable records (vuln=true) | ${output.vulnerableRecords} | ${pct(output.vulnerableRecords, output.totalFunctionRecords)} |
| Non-vulnerable records (vuln=false) | ${output.nonVulnerableRecords} | ${pct(output.nonVulnerableRecords, output.totalFunctionRecords)} |
| Records with CWE (via metadata) | ${output.recordsWithCWE} | ${pct(output.recordsWithCWE, output.totalFunctionRecords)} |
| Records with CVE (via metadata) | ${output.recordsWithCVE} | ${pct(output.recordsWithCVE, output.totalFunctionRecords)} |
| Records with commit information | ${output.recordsWithCommit} | ${pct(output.recordsWithCommit, output.totalFunctionRecords)} |
| Records with file path | ${output.recordsWithFilePath} | ${pct(output.recordsWithFilePath, output.totalFunctionRecords)} |
| Records with line info | ${output.recordsWithLineInfo} | ${pct(output.recordsWithLineInfo, output.totalFunctionRecords)} |

## Metadata Statistics

| Metric | Count |
|--------|-------|
| Metadata JSON files | ${output.metadataFiles} |
| Total fix commits in metadata | ${output.metadataCommitsTotal} |
| Commits with CVE | ${output.metadataCVECommits} |
| Commits with CWE | ${output.metadataCWECommits} |
| Unique CVEs | ${output.uniqueCVECount} |
| Unique CWEs | ${output.uniqueCWECount} |

${output.invalidFileList.length > 0 ? `## Invalid / Malformed JSON Files\n\n${output.invalidFileList.map(f => '- ' + f).join('\n')}` : '## Invalid Files\n\nNone detected.'}

${output.emptyFileList.length > 0 ? `## Empty Files\n\n${output.emptyFileList.map(f => '- ' + f).join('\n')}` : '## Empty Files\n\nNone detected.'}

---

*End of Dataset Inventory Report*
`;

fs.writeFileSync(path.join(REPORTS_DIR, 'dataset_inventory.md'), md, 'utf8');

// Print summary
console.log('\n[inventory] ====== DATASET INVENTORY SUMMARY ======');
console.log(`  Dataset files scanned:     ${output.totalJsonFiles}`);
console.log(`  Valid JSON files:          ${output.validJsonFiles}`);
console.log(`  Invalid JSON files:        ${output.invalidJsonFiles}`);
console.log(`  Organisations:             ${output.organisations}`);
console.log(`  Projects:                  ${output.projects}`);
console.log(`  Commit pairs:              ${output.commitPairs}`);
console.log(`  Total function records:    ${output.totalFunctionRecords}`);
console.log(`  Source-bearing records:    ${output.sourceBearingRecords}`);
console.log(`  Vulnerable records:        ${output.vulnerableRecords}`);
console.log(`  Non-vulnerable records:    ${output.nonVulnerableRecords}`);
console.log(`  Unique CVEs:               ${output.uniqueCVECount}`);
console.log(`  Unique CWEs:               ${output.uniqueCWECount}`);
console.log('[inventory] Reports written to reports/dataset_inventory.{json,md}');

module.exports = { output, metadataMap };
