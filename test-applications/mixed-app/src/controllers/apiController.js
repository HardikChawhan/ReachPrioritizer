/**
 * mixed-app/src/controllers/apiController.js
 * Active controller handlers. Calls activeService (vulnerable) and safeHelper (secure).
 */
'use strict';

const url = require('url');
const { processCommand, fetchExternalReport } = require('../services/activeService');
const { formatOutput, computeSystemStats, sanitizeString } = require('../utils/safeHelper');

function handleProcess(req, res) {
  const parsed = url.parse(req.url, true);
  const commandInput = parsed.query.cmd || 'default';
  
  // Call vulnerable reachable service
  processCommand(commandInput, (err, output) => {
    if (err) {
      res.writeHead(500);
      return res.end(JSON.stringify({ error: err.message }));
    }
    // Call secure reachable helper
    const formatted = formatOutput(output);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ result: formatted }));
  });
}

function handleStats(req, res) {
  // Call secure reachable helper
  const stats = computeSystemStats();
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ stats }));
}

function handleFetch(req, res) {
  const parsed = url.parse(req.url, true);
  const targetUrl = parsed.query.url;
  // Call vulnerable reachable fetch
  fetchExternalReport(targetUrl, (err, data) => {
    if (err) {
      res.writeHead(500);
      return res.end(JSON.stringify({ error: err.message }));
    }
    res.writeHead(200);
    res.end(data);
  });
}

module.exports = { handleProcess, handleStats, handleFetch };
