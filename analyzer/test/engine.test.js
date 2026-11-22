'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { analyzeProject } = require('../lib/project');
const { APPS, APPS_DIR, loadGroundTruth, findNode } = require('./groundtruth');

// ---------------------------------------------------------------- ground truth apps
for (const app of APPS) {
  test(`${app}: detection and reachability match ground truth`, () => {
    const result = analyzeProject(path.join(APPS_DIR, app));
    const gt = loadGroundTruth(app);
    for (const entry of gt.functions) {
      const node = findNode(result, entry);
      assert.ok(node, `${app}: function not found in call graph: ${entry.file}::${entry.function}`);
      const findings = result.findings.filter((f) => f.function_id === node.id);
      if (entry.is_vulnerable) {
        assert.ok(findings.length > 0, `${app}: missed vulnerability in ${node.id}`);
        assert.ok(findings.some((f) => f.cwe === entry.cwe), `${app}: ${node.id} expected ${entry.cwe}, got ${findings.map((f) => f.cwe)}`);
      } else {
        assert.strictEqual(findings.length, 0, `${app}: false positive in ${node.id}: ${findings.map((f) => f.message).join('; ')}`);
      }
      const reachable = node.reachability === 'reachable';
      assert.strictEqual(reachable, entry.is_reachable, `${app}: reachability of ${node.id} is ${node.reachability}, expected reachable=${entry.is_reachable}`);
    }
  });
}

test('secure-app produces zero findings', () => {
  const result = analyzeProject(path.join(APPS_DIR, 'secure-app'));
  assert.strictEqual(result.findings.length, 0);
});

test('reachable findings carry a call path that starts at an entry point', () => {
  const result = analyzeProject(path.join(APPS_DIR, 'vulnerable-app'));
  const f = result.findings.find((x) => x.function_id.endsWith('::runCommand'));
  assert.ok(f);
  assert.deepStrictEqual(f.call_path, [
    'src/server.js::__top_level__',
    'src/routes/files.js::setupFileRoutes',
    'src/routes/files.js::executeCommand',
    'src/controllers/fileController.js::executeCmd',
    'src/controllers/fileController.js::runCommand',
  ]);
  assert.strictEqual(f.taint, 'user_input');
  assert.deepStrictEqual(f.taint_path, [
    'src/routes/files.js::executeCommand',
    'src/controllers/fileController.js::executeCmd',
    'src/controllers/fileController.js::runCommand',
  ]);
});

// ---------------------------------------------------------------- small focused cases
function analyzeSnippet(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-test-'));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  try { return analyzeProject(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('tagged sql templates and parameterized queries are not flagged', () => {
  const r = analyzeSnippet({ 'a.js': `
    const sql = require('sql-template-tag').default;
    function a(db, id) { return db.query(sql\`SELECT * FROM t WHERE id = \${id}\`); }
    function b(db, id) { return db.query('SELECT * FROM t WHERE id = $1', [id]); }
    module.exports = { a, b };
  ` });
  assert.strictEqual(r.findings.length, 0, JSON.stringify(r.findings));
});

test('promisified exec is still a command-injection sink', () => {
  const r = analyzeSnippet({ 'a.js': `
    const util = require('util');
    const cp = require('child_process');
    const run = util.promisify(cp.exec);
    async function handler(req, res) { await run('ls ' + req.query.dir); }
    module.exports = handler;
  ` });
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].cwe, 'CWE-78');
  assert.strictEqual(r.findings[0].taint, 'user_input');
});

test('allowlist guard clause sanitizes the checked variable', () => {
  const r = analyzeSnippet({ 'a.js': `
    const { exec } = require('child_process');
    const OK = ['a', 'b'];
    function run(req) {
      const c = req.query.c;
      if (!OK.includes(c)) return;
      exec('tool ' + c);
    }
    function runBad(req) { exec('tool ' + req.query.c); }
    module.exports = { run, runBad };
  ` });
  assert.deepStrictEqual(r.findings.map((f) => f.function_name), ['runBad']);
});

test('axios config object url is checked and ESM + TypeScript files parse', () => {
  const r = analyzeSnippet({
    'src/server.ts': `
      import express, { Request, Response } from 'express';
      import { fetchIt } from './client';
      const app = express();
      app.get('/f', async (req: Request, res: Response) => { res.json(await fetchIt(req.query.u as string)); });
      app.listen(3000);
    `,
    'src/client.ts': `
      import axios from 'axios';
      export async function fetchIt(u: string): Promise<unknown> { return (await axios({ method: 'get', url: u })).data; }
    `,
  });
  const f = r.findings.find((x) => x.cwe === 'CWE-918');
  assert.ok(f, JSON.stringify(r.findings));
  assert.strictEqual(f.taint, 'user_input');
  assert.strictEqual(f.reachability, 'reachable');
});

test('hardcoded secrets ignore placeholders and env lookups', () => {
  const r = analyzeSnippet({ 'a.js': `
    const password = 'changeme';
    const apiKey = process.env.API_KEY;
    const token = 'ghp_realLookingToken123';
  ` });
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].cwe, 'CWE-798');
});
