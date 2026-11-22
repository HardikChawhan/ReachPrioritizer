// vulnerable-app/src/routes/files.js
'use strict';

const { listUserFiles, executeCmd } = require('../controllers/fileController');

function listFiles(req, res) {
  const userPath = req.query.path || '';
  const result = listUserFiles(userPath);
  res.json({ files: result });
}

function executeCommand(req, res) {
  const cmd = req.query.cmd || '';
  const result = executeCmd(cmd);
  res.json({ output: result });
}

function setupFileRoutes(app) {
  app.get('/files', listFiles);
  app.get('/execute', executeCommand);
}

module.exports = { setupFileRoutes };
