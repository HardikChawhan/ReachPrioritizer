/**
 * mixed-app/src/services/activeService.js
 * Active service layer - REACHABLE from server.js entry point.
 * Contains intentional vulnerabilities for reachability demonstration.
 */
'use strict';

const { exec } = require('child_process');
const http = require('http');

/**
 * VULNERABILITY: Command Injection (CWE-78)
 * Reachability: REACHABLE via server.js -> api.js -> apiController.js -> activeService.js
 */
function processCommand(userInput, callback) {
  // Dangerous: concatenates user input directly into system shell command
  const cmd = "echo 'Processing task: ' " + userInput;
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return callback(error, null);
    }
    callback(null, stdout);
  });
}

/**
 * VULNERABILITY: SSRF / Path Traversal in network request (CWE-918)
 * Reachability: REACHABLE via server.js -> api.js -> apiController.js -> activeService.js
 */
function fetchExternalReport(remoteUrl, callback) {
  // Dangerous: passes user-controlled URL without validation
  http.get(remoteUrl, (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => callback(null, data));
  }).on('error', (err) => callback(err, null));
}

module.exports = { processCommand, fetchExternalReport };
