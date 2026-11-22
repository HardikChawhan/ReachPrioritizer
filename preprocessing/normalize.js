/**
 * normalize.js
 * ReachPrioritizer Phase 1 — Step 2
 *
 * Reads the raw JsVul dataset and produces:
 *   data/processed/jsvul_normalized.jsonl
 *
 * Each record contains fields that ACTUALLY exist in the source data.
 * Fields not present are set to null.
 * Provenance is preserved so every record traces back to its raw JSON file.
 *
 * SAFETY: Read-only on raw data. Writes only to data/processed/.
 */

'use strict';

const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

// ── Paths ────────────────────────────────────────────────────────────────────
const ROOT       = path.resolve(__dirname, '..');
const FUNCTIONS  = path.join(ROOT, 'data', 'raw', 'tools', 'jsvul', '08_final', 'functions');
const METADATA   = path.join(ROOT, 'data', 'raw', 'tools', 'jsvul', '08_final', 'metadata');
const PROCESSED  = path.join(ROOT, 'data', 'processed');
const OUT_FILE   = path.join(PROCESSED, 'jsvul_normalized.jsonl');

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

function safeJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (_) { return null; }
}

// ── Source normalization (for hashing, NOT for model input) ─────────────────
// We normalize only for the purpose of duplicate detection.
// We do NOT rename variables or change semantics.
function normalizeSource(src) {
  if (typeof src !== 'string') return null;
  return src
    .replace(/\r\n/g, '\n')   // CRLF → LF
    .replace(/\r/g, '\n')     // CR → LF
    .replace(/[ \t]+\n/g, '\n')  // trailing whitespace per line
    .replace(/\n{3,}/g, '\n\n')  // collapse excess blank lines
    .trim();
}

function sha256(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// ── Load metadata ────────────────────────────────────────────────────────────
console.log('[normalize] Loading metadata...');
const metadataMap = {};

function walkMetadata(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { walkMetadata(full); continue; }
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue;

    const data = safeJson(full);
    if (!data) continue;

    const rel   = path.relative(METADATA, full).replace(/\\/g, '/');
    const parts = rel.split('/');
    const org   = parts[0];
    const proj  = parts[1].replace(/\.json$/, '');

    for (const sha of Object.keys(data)) {
      const rec = data[sha];
      metadataMap[`${org}/${proj}/${sha}`] = {
        cve:          rec.cve          || [],
        cwe:          rec.cwe          || [],
        github:       rec.github       || [],
        vuln_sha:     rec.vuln_sha     || null,
        commit_msg:   rec.commit_msg   || null,
        publish_time: rec.publish_time || null,
        additions:    rec.additions    ?? null,
        deletions:    rec.deletions    ?? null,
        changes:      rec.changes      ?? null,
        files:        rec.files        || [],
        sources:      rec.sources      || {},
      };
    }
  }
}
walkMetadata(METADATA);
console.log(`[normalize] Loaded ${Object.keys(metadataMap).length} metadata entries.`);

// ── Walk functions and emit records ─────────────────────────────────────────
ensureDir(PROCESSED);
const out   = fs.createWriteStream(OUT_FILE, { encoding: 'utf8' });
let   count = 0;
let   skipped = 0;

function walkFunctions(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { walkFunctions(full); continue; }
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue;

    // Path: functions/<org>/<project>/<sha>/<vuln|fix>.json
    const rel   = path.relative(FUNCTIONS, full).replace(/\\/g, '/');
    const parts = rel.split('/');
    if (parts.length !== 4) continue;  // unexpected depth

    const [org, project, fix_commit_sha, filename] = parts;
    const file_type = filename.replace('.json', '');  // "vuln" or "fix"
    const meta_key  = `${org}/${project}/${fix_commit_sha}`;
    const meta      = metadataMap[meta_key] || null;

    const data = safeJson(full);
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      skipped++;
      continue;
    }

    for (const source_file of Object.keys(data)) {
      const functions = data[source_file];
      if (!Array.isArray(functions)) { skipped++; continue; }

      for (let idx = 0; idx < functions.length; idx++) {
        const fn = functions[idx];
        if (!fn || typeof fn !== 'object') { skipped++; continue; }

        const original_source  = typeof fn.function_body === 'string' ? fn.function_body : null;
        const normalized_source = original_source !== null ? normalizeSource(original_source) : null;

        const raw_sha256 = original_source !== null
          ? sha256(original_source)
          : null;
        const normalized_sha256 = normalized_source !== null
          ? sha256(normalized_source)
          : null;

        // Unique sample ID: org + project + sha + file_type + source_file + idx
        const sample_id = sha256(
          `${org}|${project}|${fix_commit_sha}|${file_type}|${source_file}|${idx}`
        ).substring(0, 16);

        const record = {
          sample_id,
          // Provenance
          organisation:    org,
          project,
          fix_commit_sha,
          file_type,         // "vuln" or "fix"
          source_file,       // e.g. "lib/response.js"
          source_file_index: idx,
          raw_source_path:   rel,

          // Function metadata
          function_name:  fn.function_name  || null,
          node_type:      fn.node_type      || null,
          start_line:     fn.start_line     ?? null,
          end_line:       fn.end_line       ?? null,
          start_column:   fn.start_column   ?? null,
          end_column:     fn.end_column     ?? null,

          // Label
          label:    fn.vuln === true ? 1 : 0,  // 1=vulnerable, 0=benign
          vuln_raw: fn.vuln,
          affected: fn.affected,                 // synonym field preserved

          // Source
          original_source,
          normalized_source,
          source_length:    original_source !== null ? original_source.length : null,
          line_count:       original_source !== null ? original_source.split('\n').length : null,

          // Hashes
          raw_source_sha256:        raw_sha256,
          normalized_source_sha256: normalized_sha256,

          // Vulnerability metadata (from metadata/ join)
          cve:          meta ? meta.cve          : [],
          cwe:          meta ? meta.cwe          : [],
          github:       meta ? meta.github       : [],
          vuln_sha:     meta ? meta.vuln_sha     : null,
          commit_msg:   meta ? meta.commit_msg   : null,
          publish_time: meta ? meta.publish_time : null,
          meta_additions: meta ? meta.additions  : null,
          meta_deletions: meta ? meta.deletions  : null,
          meta_changes:   meta ? meta.changes    : null,

          // Language (inferred — not present in source JSON)
          language: 'javascript',

          // Pair identifier (same for vuln.json and fix.json of the same commit)
          pair_id: `${org}/${project}/${fix_commit_sha}`,
        };

        out.write(JSON.stringify(record) + '\n');
        count++;

        if (count % 10000 === 0) {
          console.log(`[normalize]   ${count} records written...`);
        }
      }
    }
  }
}

console.log('[normalize] Processing function records...');
walkFunctions(FUNCTIONS);
out.end();

console.log(`[normalize] Done. ${count} records written → ${OUT_FILE}`);
if (skipped > 0) console.log(`[normalize] Skipped ${skipped} malformed entries.`);

module.exports = { recordCount: count };
