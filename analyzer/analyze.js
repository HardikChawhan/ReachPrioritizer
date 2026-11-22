#!/usr/bin/env node
'use strict';
/**
 * ReachPrioritizer analysis engine — single entry point.
 *
 *   node analyzer/analyze.js --project <dir> [--output result.json] [--with-source]
 *                            [--entry-points file.js,file.js:functionName] [--pretty]
 *
 * Produces one JSON document containing: functions (call-graph nodes), call edges,
 * entry points, reachability + call paths for every function, and taint-aware
 * security findings.
 */
const fs = require('fs');
const path = require('path');
const minimist = require('minimist');
const { analyzeProject } = require('./lib/project');

const argv = minimist(process.argv.slice(2), {
  string: ['project', 'output', 'entry-points'],
  boolean: ['help', 'with-source', 'pretty', 'include-tests'],
  alias: { h: 'help', p: 'project', o: 'output', e: 'entry-points' },
});

if (argv.help || !argv.project) {
  console.log('Usage: node analyzer/analyze.js --project <dir> [--output <file>] [--with-source] [--entry-points a.js,b.js:fn] [--pretty]');
  process.exit(argv.help ? 0 : 1);
}

const projectDir = path.resolve(argv.project);
if (!fs.existsSync(projectDir) || !fs.statSync(projectDir).isDirectory()) {
  console.error(`Error: project directory not found: ${projectDir}`);
  process.exit(1);
}

const started = Date.now();
const result = analyzeProject(projectDir, {
  withSource: argv['with-source'],
  includeTests: argv['include-tests'],
  entryPoints: argv['entry-points'] ? String(argv['entry-points']).split(',').map((s) => s.trim()).filter(Boolean) : [],
});
result.elapsed_ms = Date.now() - started;

const text = JSON.stringify(result, null, argv.pretty ? 2 : 0);
if (argv.output) {
  const out = path.resolve(argv.output);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, text, 'utf8');
  console.error(`[analyzer] ${result.stats.files_analyzed} files, ${result.stats.functions} functions, ${result.stats.edges} edges, ${result.stats.findings} findings in ${result.elapsed_ms} ms -> ${out}`);
} else {
  process.stdout.write(text + '\n');
}
