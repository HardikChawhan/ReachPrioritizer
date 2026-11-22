/**
 * split.js
 * ReachPrioritizer Phase 1 — Step 9
 *
 * Creates repository-disjoint train/validation/test splits.
 * Produces:
 *   data/processed/splits/train.jsonl
 *   data/processed/splits/validation.jsonl
 *   data/processed/splits/test.jsonl
 *   data/processed/split_manifest.json
 *
 * SAFETY: Read-only on raw data. Writes only to data/processed/splits/.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Config ────────────────────────────────────────────────────────────────────
const RANDOM_SEED = 42;
const TARGET_TRAIN = 0.80;
const TARGET_VAL   = 0.10;
const TARGET_TEST  = 0.10;
const DATASET_VERSION     = '1.0.0';
const PREPROCESSING_VERSION = '1.0.0';

// ── Paths ────────────────────────────────────────────────────────────────────
const ROOT        = path.resolve(__dirname, '..');
const CLEAN       = path.join(ROOT, 'data', 'processed', 'jsvul_clean.jsonl');
const SPLITS_DIR  = path.join(ROOT, 'data', 'processed', 'splits');
const MANIFEST    = path.join(ROOT, 'data', 'processed', 'split_manifest.json');
const REPORTS_DIR = path.join(ROOT, 'reports');

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ── Deterministic seeded PRNG (Mulberry32) ────────────────────────────────────
function mulberry32(seed) {
  let s = seed >>> 0;
  return function() {
    s |= 0; s = s + 0x6D2B79F5 | 0;
    let t = Math.imul(s ^ s >>> 15, 1 | s);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

function shuffle(arr, rng) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ── Load records ─────────────────────────────────────────────────────────────
console.log('[split] Loading clean records...');
const lines = fs.readFileSync(CLEAN, 'utf8')
  .split('\n')
  .filter(l => l.trim().length > 0);

const records = [];
for (const l of lines) {
  try { records.push(JSON.parse(l)); }
  catch (_) { /* skip */ }
}
console.log(`[split] ${records.length} records loaded.`);

// ── Group records by repository ───────────────────────────────────────────────
const repoGroups = {};
for (const rec of records) {
  const repo = `${rec.organisation}/${rec.project}`;
  if (!repoGroups[repo]) repoGroups[repo] = [];
  repoGroups[repo].push(rec);
}

const repos = Object.keys(repoGroups);
console.log(`[split] ${repos.length} distinct repositories.`);

// ── Check for publish_time availability ──────────────────────────────────────
// JsVul metadata contains publish_time. We can use it for chronological ordering.
// If a repo has at least one record with publish_time, we use it to sort repos.
function getRepoDate(repoRecords) {
  for (const r of repoRecords) {
    if (r.publish_time && r.publish_time.year) {
      const { year, month = 1, day = 1 } = r.publish_time;
      return new Date(year, month - 1, day).getTime();
    }
  }
  return null;
}

const repoDates = repos.map(r => ({ repo: r, date: getRepoDate(repoGroups[r]) }));
const reposWithDate    = repoDates.filter(x => x.date !== null);
const reposWithoutDate = repoDates.filter(x => x.date === null);

console.log(`[split] Repos with publish_time: ${reposWithDate.length}, without: ${reposWithoutDate.length}`);

// Strategy: sort by publish_time where available, then shuffle remainder with seed
// Chronological ordering reduces temporal leakage.
reposWithDate.sort((a, b) => a.date - b.date);

const rng = mulberry32(RANDOM_SEED);
const shuffledWithoutDate = shuffle(reposWithoutDate.map(x => x.repo), rng);
const sortedWithDate      = reposWithDate.map(x => x.repo);

// Combine: dated repos first (chronological), then undated (random)
const orderedRepos = [...sortedWithDate, ...shuffledWithoutDate];

// ── Assign repositories to splits ─────────────────────────────────────────────
// Count records per repo (for proportional sizing)
const totalRecords = records.length;
const trainTarget  = totalRecords * TARGET_TRAIN;
const valTarget    = totalRecords * TARGET_VAL;

const trainRepos = new Set();
const valRepos   = new Set();
const testRepos  = new Set();

let trainCount = 0;
let valCount   = 0;

// Simple greedy allocation: fill train until target, then val, then test
for (const repo of orderedRepos) {
  const n = repoGroups[repo].length;
  if (trainCount < trainTarget) {
    trainRepos.add(repo);
    trainCount += n;
  } else if (valCount < valTarget) {
    valRepos.add(repo);
    valCount += n;
  } else {
    testRepos.add(repo);
  }
}

// ── Verify disjointness ──────────────────────────────────────────────────────
function intersect(setA, setB) {
  return [...setA].filter(x => setB.has(x));
}

const tvIntersect = intersect(trainRepos, valRepos);
const ttIntersect = intersect(trainRepos, testRepos);
const vtIntersect = intersect(valRepos,   testRepos);

if (tvIntersect.length > 0 || ttIntersect.length > 0 || vtIntersect.length > 0) {
  console.error('[split] CRITICAL: Split sets are NOT disjoint!');
  console.error('Train ∩ Val:', tvIntersect);
  console.error('Train ∩ Test:', ttIntersect);
  console.error('Val ∩ Test:', vtIntersect);
  process.exit(1);
}
console.log('[split] ✅ Split disjointness verified: train ∩ val = ∅, train ∩ test = ∅, val ∩ test = ∅');

// ── Assign records ────────────────────────────────────────────────────────────
const trainRecords = [];
const valRecords   = [];
const testRecords  = [];

for (const rec of records) {
  const repo = `${rec.organisation}/${rec.project}`;
  rec.split  = trainRepos.has(repo) ? 'train'
             : valRepos.has(repo)   ? 'validation'
             :                        'test';

  if (rec.split === 'train')      trainRecords.push(rec);
  else if (rec.split === 'validation') valRecords.push(rec);
  else                            testRecords.push(rec);
}

// ── Write split files ─────────────────────────────────────────────────────────
ensureDir(SPLITS_DIR);

function writeJsonl(filepath, recs) {
  fs.writeFileSync(filepath, recs.map(r => JSON.stringify(r)).join('\n') + '\n', 'utf8');
}

writeJsonl(path.join(SPLITS_DIR, 'train.jsonl'),      trainRecords);
writeJsonl(path.join(SPLITS_DIR, 'validation.jsonl'), valRecords);
writeJsonl(path.join(SPLITS_DIR, 'test.jsonl'),       testRecords);

// ── Split manifest ────────────────────────────────────────────────────────────
function labelDist(recs) {
  let vuln = 0, benign = 0;
  for (const r of recs) r.label === 1 ? vuln++ : benign++;
  return { vulnerable: vuln, benign, total: recs.length };
}

const manifest = {
  created_at:           new Date().toISOString(),
  random_seed:          RANDOM_SEED,
  dataset_version:      DATASET_VERSION,
  preprocessing_version: PREPROCESSING_VERSION,
  split_strategy:       'repository_disjoint_chronological',
  timestamp_available:  reposWithDate.length > 0,
  repos_with_publish_time: reposWithDate.length,
  repos_without_publish_time: reposWithoutDate.length,
  target_proportions: { train: TARGET_TRAIN, validation: TARGET_VAL, test: TARGET_TEST },
  actual_proportions: {
    train:      trainRecords.length / totalRecords,
    validation: valRecords.length   / totalRecords,
    test:       testRecords.length  / totalRecords,
  },
  splits: {
    train: {
      records:      trainRecords.length,
      repositories: trainRepos.size,
      label_dist:   labelDist(trainRecords),
      repository_ids: [...trainRepos],
    },
    validation: {
      records:      valRecords.length,
      repositories: valRepos.size,
      label_dist:   labelDist(valRecords),
      repository_ids: [...valRepos],
    },
    test: {
      records:      testRecords.length,
      repositories: testRepos.size,
      label_dist:   labelDist(testRecords),
      repository_ids: [...testRepos],
    },
  },
  disjointness_checks: {
    train_val_intersection:  tvIntersect.length,
    train_test_intersection: ttIntersect.length,
    val_test_intersection:   vtIntersect.length,
    all_disjoint: tvIntersect.length === 0 && ttIntersect.length === 0 && vtIntersect.length === 0,
  },
  sample_ids: records.map(r => ({ sample_id: r.sample_id, repo: `${r.organisation}/${r.project}`, split: r.split })),
};

fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2), 'utf8');

// ── Print summary ─────────────────────────────────────────────────────────────
const pct = (n, d) => `${((n / d) * 100).toFixed(1)}%`;

console.log(`\n[split] ====== SPLIT SUMMARY ======`);
console.log(`  Total records:      ${totalRecords}`);
console.log(`  Repositories:       ${repos.length}`);
console.log(`  Train:              ${trainRecords.length} records, ${trainRepos.size} repos (${pct(trainRecords.length, totalRecords)})`);
console.log(`    Vulnerable:       ${manifest.splits.train.label_dist.vulnerable}`);
console.log(`    Benign:           ${manifest.splits.train.label_dist.benign}`);
console.log(`  Validation:         ${valRecords.length} records, ${valRepos.size} repos (${pct(valRecords.length, totalRecords)})`);
console.log(`    Vulnerable:       ${manifest.splits.validation.label_dist.vulnerable}`);
console.log(`    Benign:           ${manifest.splits.validation.label_dist.benign}`);
console.log(`  Test:               ${testRecords.length} records, ${testRepos.size} repos (${pct(testRecords.length, totalRecords)})`);
console.log(`    Vulnerable:       ${manifest.splits.test.label_dist.vulnerable}`);
console.log(`    Benign:           ${manifest.splits.test.label_dist.benign}`);
console.log(`  Disjointness:       ✅ verified`);
console.log('[split] Split files written to data/processed/splits/');

module.exports = { manifest };
