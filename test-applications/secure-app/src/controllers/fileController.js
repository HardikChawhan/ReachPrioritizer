// secure-app/src/controllers/fileController.js
// SECURE implementations: path validation, execFile allowlist, HTML escaping
'use strict';

const fs = require('fs');
const path = require('path');
const child_process = require('child_process');

const ALLOWED_DATA_DIR = path.resolve(__dirname, '../../data');
const ALLOWED_COMMANDS = ['ls', 'pwd', 'echo'];

/**
 * SECURE: Path Traversal prevention via path.resolve + boundary check.
 * Resolves the full path and verifies it stays within the allowed directory.
 */
function listUserFiles(userPath) {
  if (typeof userPath !== 'string') {
    return { error: 'Invalid path parameter' };
  }

  // SECURE: resolve full path and verify it stays within allowed directory
  const resolvedPath = path.resolve(ALLOWED_DATA_DIR, userPath);
  if (!resolvedPath.startsWith(ALLOWED_DATA_DIR + path.sep) &&
      resolvedPath !== ALLOWED_DATA_DIR) {
    console.log('[SECURE] Path traversal attempt blocked:', userPath);
    return { error: 'Access denied: path outside allowed directory' };
  }

  try {
    const content = fs.readFileSync(resolvedPath, 'utf8');
    return content;
  } catch (err) {
    return { error: 'File not found or not readable' };
  }
}

/**
 * SECURE: Command Injection prevention via allowlist + execFile (no shell).
 * Uses execFileSync with an argument array — shell metacharacters are inert.
 */
function runCommand(cmd) {
  if (!ALLOWED_COMMANDS.includes(cmd)) {
    console.log('[SECURE] Command not in allowlist, blocked:', cmd);
    return { error: 'Command not permitted' };
  }

  try {
    // SECURE: execFileSync does not invoke a shell; args are passed directly
    const output = child_process.execFileSync(cmd, [], { timeout: 5000 });
    return output.toString();
  } catch (err) {
    return { error: 'Command execution failed' };
  }
}

function executeCmd(cmd) {
  return runCommand(cmd);
}

/**
 * SECURE: HTML encoding prevents XSS via innerHTML.
 * All dynamic data is escaped before being embedded in HTML.
 */
function renderPage(template, data) {
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // SECURE: data is escaped before insertion into HTML
  const html = '<div class="content">' + escapeHtml(template) + '</div>' +
               '<div class="data">' + escapeHtml(data) + '</div>';
  return html;
}

module.exports = { listUserFiles, runCommand, executeCmd, renderPage };
