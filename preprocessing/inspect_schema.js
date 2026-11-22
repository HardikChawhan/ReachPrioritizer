/**
 * inspect_schema.js
 * ReachPrioritizer Phase 1 — Step 0
 *
 * Inspects representative JSON files from both functions/ and metadata/
 * directories and produces reports/jsvul_schema_report.md.
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

// ── Helpers ──────────────────────────────────────────────────────────────────
function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

/** Collect up to `limit` .json files under `dir` */
function collectJsonFiles(dir, limit = Infinity) {
  const results = [];
  function walk(d) {
    if (results.length >= limit) return;
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      if (results.length >= limit) break;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.json')) results.push(full);
    }
  }
  walk(dir);
  return results;
}

/** Safely parse JSON; return null on failure */
function safeJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (_) { return null; }
}

// ── Collect representative samples ───────────────────────────────────────────
// Pick samples from different org/repo directories
function pickRepresentativeSamples(dir, count) {
  const orgDirs = fs.readdirSync(dir, { withFileTypes: true })
    .filter(e => e.isDirectory())
    .map(e => path.join(dir, e.name));

  const chosen = [];
  const step = Math.max(1, Math.floor(orgDirs.length / count));
  for (let i = 0; i < orgDirs.length && chosen.length < count; i += step) {
    const files = collectJsonFiles(orgDirs[i], 2);
    chosen.push(...files.slice(0, 2));
  }
  return chosen.slice(0, count);
}

const functionSamples  = pickRepresentativeSamples(FUNCTIONS, 12);
const metadataSamples  = pickRepresentativeSamples(METADATA,  8);

// ── Analyse function JSON files ───────────────────────────────────────────────
const functionObservations = [];

for (const fp of functionSamples) {
  const rel  = path.relative(FUNCTIONS, fp);
  const data = safeJson(fp);
  if (!data) { functionObservations.push({ file: rel, error: 'parse failure' }); continue; }

  // Structure: { "<filename.js>": [ { ...function record... }, ... ] }
  const fileKeys = Object.keys(data);
  const allFunctions = [];
  for (const k of fileKeys) {
    if (Array.isArray(data[k])) allFunctions.push(...data[k]);
  }

  const sample = allFunctions[0] || {};
  functionObservations.push({
    file:           rel,
    topLevelKeys:   fileKeys,
    functionCount:  allFunctions.length,
    functionKeys:   Object.keys(sample),
    exampleRecord:  {
      function_name: sample.function_name,
      node_type:     sample.node_type,
      vuln:          sample.vuln,
      affected:      sample.affected,
      start_line:    sample.start_line,
      end_line:      sample.end_line,
      start_column:  sample.start_column,
      end_column:    sample.end_column,
      source_length: typeof sample.function_body === 'string' ? sample.function_body.length : null,
    }
  });
}

// ── Analyse metadata JSON files ───────────────────────────────────────────────
const metadataObservations = [];

for (const fp of metadataSamples) {
  const rel  = path.relative(METADATA, fp);
  const data = safeJson(fp);
  if (!data) { metadataObservations.push({ file: rel, error: 'parse failure' }); continue; }

  // Structure: { "<fix_commit_sha>": { ...commit record... } }
  const commitShas = Object.keys(data);
  const firstCommit = commitShas.length > 0 ? data[commitShas[0]] : {};
  metadataObservations.push({
    file:         rel,
    commitCount:  commitShas.length,
    commitKeys:   Object.keys(firstCommit),
    exampleCommit: {
      additions:    firstCommit.additions,
      deletions:    firstCommit.deletions,
      changes:      firstCommit.changes,
      commit_msg:   typeof firstCommit.commit_msg === 'string' ? firstCommit.commit_msg.substring(0, 80) + '…' : null,
      cve:          firstCommit.cve,
      cwe:          firstCommit.cwe,
      github:       firstCommit.github,
      vuln_sha:     firstCommit.vuln_sha,
      publish_time: firstCommit.publish_time,
      files:        firstCommit.files,
      sources:      firstCommit.sources ? Object.keys(firstCommit.sources) : null,
    }
  });
}

// ── Build report ─────────────────────────────────────────────────────────────
function fmtJson(obj) {
  return '```json\n' + JSON.stringify(obj, null, 2) + '\n```';
}

const now = new Date().toISOString();

const report = `# JsVul Schema Report

> Generated: ${now}
> Scope: JavaScript / Node.js only

---

## Overview

The JsVul dataset (\`08_final/\`) has two parallel directory trees:

\`\`\`
08_final/
├── functions/   <organisation>/<project>/<fix_commit_sha>/{vuln.json, fix.json}
└── metadata/    <organisation>/<project>.json
\`\`\`

### Directory path anatomy (functions/)

\`\`\`
functions/
  <organisation>/          ← GitHub organisation or owner (e.g. "expressjs")
    <project>/             ← Repository / package name  (e.g. "express")
      <fix_commit_sha>/    ← SHA-1 of the fixing commit (40 hex chars)
        vuln.json          ← Functions extracted from the VULNERABLE version
        fix.json           ← Functions extracted from the FIXED version
\`\`\`

Each commit directory always contains a **pair**: \`vuln.json\` + \`fix.json\`.

---

## 1. functions/ JSON Schema

### Top-level structure

Each \`vuln.json\` or \`fix.json\` is a JSON **object** whose keys are **source file paths**
(relative to the project root, e.g. \`"lib/response.js"\`) and whose values are
**arrays of function records**.

\`\`\`
{
  "<relative_file_path>": [
    { <function_record> },
    ...
  ],
  ...
}
\`\`\`

### Function record fields

| Field           | Type    | Always present | Description |
|-----------------|---------|----------------|-------------|
| \`function_body\`  | string  | ✅ Yes         | Full JavaScript source of the function |
| \`function_name\`  | string  | ✅ Yes         | Name of the function |
| \`node_type\`      | string  | ✅ Yes         | AST node type (e.g. \`FunctionExpression\`, \`ClassMethod\`) |
| \`vuln\`           | boolean | ✅ Yes         | \`true\` = this function is vulnerable; \`false\` = not |
| \`affected\`       | boolean | ✅ Yes         | Synonym / redundant with \`vuln\` in observed data |
| \`start_line\`     | integer | ✅ Yes         | Starting line number in the source file |
| \`end_line\`       | integer | ✅ Yes         | Ending line number in the source file |
| \`start_column\`   | integer | ✅ Yes         | Starting column |
| \`end_column\`     | integer | ✅ Yes         | Ending column |

#### Fields NOT present in the inspected JsVul function JSON schema

| Field | Status |
|-------|--------|
| \`language\` | Not present in the inspected JsVul JSON schema. Language inferred from repository context (JavaScript / Node.js). |
| \`cve\` | Not present in function records. Present in **metadata** files. |
| \`cwe\` | Not present in function records. Present in **metadata** files. |
| \`commit\` | Not present in function records. Encoded in **directory path** (fix_commit_sha). |
| \`version\` | Not present in function records. |
| \`repository\` | Not present in function records. Encoded in **directory path**. |
| \`project\` | Not present in function records. Encoded in **directory path**. |
| \`pair_id\` | Not present as an explicit field. Pair is implicit: same commit SHA directory contains both vuln.json and fix.json. |
| \`train/test split indicators\` | Not present in the inspected JsVul JSON schema. |
| \`timestamps\` | Not present in function records. Present in **metadata** (publish_time). |
| \`file SHA\` | Not present in function records. Present in metadata files entry. |

### Representative function record samples

${functionObservations.map((o, i) => `#### Sample ${i + 1}: \`${o.file}\`

${o.error ? `**Parse error:** ${o.error}` : `- Top-level file keys: \`${o.topLevelKeys.join('", "')}\`
- Function records in file: ${o.functionCount}
- Function record keys: \`${(o.functionKeys || []).join('", "')}\`
- Example values:
${fmtJson(o.exampleRecord)}`}
`).join('\n')}

---

## 2. metadata/ JSON Schema

### Top-level structure

Each metadata file corresponds to one **project** (e.g. \`metadata/expressjs/express.json\`).
It is a JSON **object** keyed by **fix commit SHA** (same SHA as the directory in \`functions/\`).

\`\`\`
{
  "<fix_commit_sha>": {
    <commit_metadata_record>
  },
  ...
}
\`\`\`

### Commit metadata record fields

| Field          | Type          | Always present | Description |
|----------------|---------------|----------------|-------------|
| \`additions\`    | integer       | ✅ Yes         | Lines added in the fix commit |
| \`deletions\`    | integer       | ✅ Yes         | Lines deleted in the fix commit |
| \`changes\`      | integer       | ✅ Yes         | Total changed lines |
| \`commit_msg\`   | string        | ✅ Yes         | Git commit message |
| \`cve\`          | array<string> | ✅ Yes         | CVE identifiers (e.g. ["CVE-2024-47178"]) |
| \`cwe\`          | array<string> | ✅ Yes         | CWE identifiers (e.g. ["CWE-208"]) |
| \`github\`       | array<string> | ✅ Yes         | GHSA advisory IDs (e.g. ["GHSA-7p89-p6hx-q4fw"]) |
| \`files\`        | array<object> | ✅ Yes         | Files changed in this commit (see below) |
| \`vuln_sha\`     | string        | ✅ Yes         | SHA-1 of the vulnerable commit (before the fix) |
| \`publish_time\` | object        | ✅ Yes         | Vulnerability publish date {day, month, year} |
| \`sources\`      | object        | ✅ Yes         | Source databases (nvd, osv) with cross-referenced IDs |

### Metadata \`files\` entry fields

| Field       | Type    | Description |
|-------------|---------|-------------|
| \`filename\`  | string  | File path changed (e.g. "lib/response.js") |
| \`additions\` | integer | Lines added in this file |
| \`deletions\` | integer | Lines deleted in this file |
| \`changes\`   | integer | Total line changes in this file |
| \`sha\`       | string  | Blob SHA of the file after the fix |
| \`status\`    | string  | Git status (e.g. "modified") |

### Metadata \`sources\` structure

\`\`\`json
{
  "nvd": { "cve": [...], "github": [...] },
  "osv": { "cve": [...], "github": [...] }
}
\`\`\`

### Representative metadata samples

${metadataObservations.map((o, i) => `#### Metadata Sample ${i + 1}: \`${o.file}\`

${o.error ? `**Parse error:** ${o.error}` : `- Fix commits in file: ${o.commitCount}
- Commit record keys: \`${(o.commitKeys || []).join('", "')}\`
- Example commit metadata:
${fmtJson(o.exampleCommit)}`}
`).join('\n')}

---

## 3. Pairing Mechanism (Vulnerable / Fixed)

The dataset uses an **implicit pair** structure encoded in the **file system path**:

\`\`\`
functions/<org>/<project>/<fix_commit_sha>/vuln.json   ← vulnerable version
functions/<org>/<project>/<fix_commit_sha>/fix.json    ← fixed version
\`\`\`

The **pair identifier** is: \`<org>/<project>/<fix_commit_sha>\`

The corresponding metadata is located at:
\`\`\`
metadata/<org>/<project>.json → key: <fix_commit_sha>
    .vuln_sha  ← SHA of the vulnerable commit
    .cve       ← CVE(s) associated with this vulnerability
    .cwe       ← CWE(s) associated with this vulnerability
\`\`\`

### Critical split constraint

Because a vulnerable/fixed pair must never be split across train and test:
- The **fix_commit_sha** (= pair_id) is treated as one **leakage unit**
- The **repository** (org/project) is treated as one **disjoint unit**

---

## 4. Label Field

The primary label field in each **function record** is:

\`\`\`
"vuln": true   ← vulnerable function
"vuln": false  ← non-vulnerable (benign) function
\`\`\`

The \`affected\` field appears to be a synonym for \`vuln\` in the observed data.
Both will be cross-checked during normalization.

---

## 5. Source Code Field

The source code of each function is stored in:

\`\`\`
"function_body": "<JavaScript source string>"
\`\`\`

This is the field that will be used for:
- JavaScript AST validation (@babel/parser)
- Hashing / duplicate detection
- Normalization
- Model input

---

## 6. Provenance Encoding

All metadata needed to trace a record back to its origin is encoded in the
**directory path structure**:

| Provenance field | Source |
|------------------|--------|
| organisation     | directory: \`functions/<org>/\` |
| project/package  | directory: \`functions/<org>/<project>/\` |
| fix_commit_sha   | directory: \`functions/<org>/<project>/<sha>/\` |
| file_type        | filename: \`vuln.json\` or \`fix.json\` |
| source_file      | JSON key inside the file (e.g. \`"lib/response.js"\`) |
| CVE / CWE        | metadata file: \`metadata/<org>/<project>.json\` |
| vuln_sha         | metadata file: \`metadata/<org>/<project>.json\` |
| publish_time     | metadata file: \`metadata/<org>/<project>.json\` |

---

## 7. Fields Explicitly NOT Present

The following fields are **not present** in the inspected JsVul JSON schema:

- \`language\` field in function records
- Pre-labelled train/test split indicators
- Function-level CVE/CWE (only available via metadata join)
- Token counts
- Any ML embedding or feature vectors
- File hash of source files
- Author / committer information
- Repository URL (inferrable from org/project path)
- Timestamps on function records (only publish_time in metadata)

---

*End of JsVul Schema Report*
`;

ensureDir(REPORTS_DIR);
fs.writeFileSync(path.join(REPORTS_DIR, 'jsvul_schema_report.md'), report, 'utf8');

console.log('[inspect_schema] Schema report written to reports/jsvul_schema_report.md');
console.log(`[inspect_schema] Analysed ${functionSamples.length} function files and ${metadataSamples.length} metadata files`);
