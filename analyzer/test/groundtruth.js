'use strict';
/** Shared helpers: match ground-truth entries to analyzer nodes. */
const fs = require('fs');
const path = require('path');

const APPS_DIR = path.resolve(__dirname, '..', '..', 'test-applications');
const APPS = ['vulnerable-app', 'secure-app', 'mixed-app', 'express-app'];

function loadGroundTruth(app) {
  return JSON.parse(fs.readFileSync(path.join(APPS_DIR, app, 'ground-truth.json'), 'utf8'));
}

function findNode(result, gt) {
  const inFile = result.nodes.filter((n) => n.file_path === gt.file);
  if (gt.line) {
    const containing = inFile.filter((n) => n.node_type !== 'Module' && n.start_line <= gt.line && gt.line <= n.end_line);
    containing.sort((a, b) => (a.end_line - a.start_line) - (b.end_line - b.start_line));
    return containing[0] || null;
  }
  return inFile.find((n) => n.name === gt.function) || inFile.find((n) => n.short === gt.function) || null;
}

module.exports = { APPS, APPS_DIR, loadGroundTruth, findNode };
