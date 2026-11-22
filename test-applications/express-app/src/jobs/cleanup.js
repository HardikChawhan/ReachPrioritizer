'use strict';
const fs = require('fs');
const path = require('path');

const TMP_DIR = '/tmp/express-app';

// SECURE: only touches file names produced by readdirSync on a constant directory
function cleanTmp() {
  for (const name of fs.readdirSync(TMP_DIR)) {
    fs.rmSync(path.join(TMP_DIR, name), { force: true });
  }
}

function startCleanupJob() {
  setInterval(cleanTmp, 60 * 60 * 1000);
}

module.exports = { startCleanupJob, cleanTmp };
