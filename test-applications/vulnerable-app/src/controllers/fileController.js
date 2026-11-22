// vulnerable-app/src/controllers/fileController.js
// CWE-22: Path Traversal, CWE-78: Command Injection, CWE-79: XSS
'use strict';

const fs = require('fs');
const child_process = require('child_process');

/**
 * VULNERABLE: Path Traversal (CWE-22)
 * User-controlled path is concatenated directly without normalization.
 * Attacker can read arbitrary files: path = "../../etc/passwd"
 */
function listUserFiles(userPath) {
  try {
    // VULNERABLE: no path validation or normalization
    const fullPath = '../data/' + userPath;
    console.log('[VULN] Reading path:', fullPath);
    const content = fs.readFileSync(fullPath, 'utf8');
    return content;
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * VULNERABLE: Command Injection (CWE-78)
 * User input is appended to shell command string without escaping.
 * Attacker can inject: cmd = "; rm -rf /" or cmd = "| cat /etc/passwd"
 */
function runCommand(cmd) {
  // VULNERABLE: shell metacharacters in cmd are interpreted by shell
  const command = 'ls ' + cmd;
  console.log('[VULN] Executing command:', command);
  try {
    const output = child_process.execSync(command, { timeout: 5000 });
    return output.toString();
  } catch (err) {
    return { error: err.message };
  }
}

// Wrapper used by route handler
function executeCmd(cmd) {
  return runCommand(cmd);
}

/**
 * VULNERABLE: Cross-Site Scripting via innerHTML (CWE-79)
 * Template data is inserted directly into HTML without encoding.
 * Attacker can inject: data = "<script>alert(1)</script>"
 */
function renderPage(template, data) {
  // VULNERABLE: data is not HTML-encoded before insertion
  const html = '<div class="content">' + template + '</div>' +
               '<div class="data">' + data + '</div>';
  return html;
}

module.exports = { listUserFiles, runCommand, executeCmd, renderPage };
