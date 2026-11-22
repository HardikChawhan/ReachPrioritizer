/**
 * mixed-app/src/legacy/legacyProcessor.js
 * Legacy processor code from an abandoned migration.
 * CRITICAL NOTE: This module is NOT imported, referenced, or executed from server.js.
 * Reachability: UNREACHABLE from application entry points.
 * 
 * Demonstrates the core research thesis:
 * Even though this code has severe vulnerabilities (SQLi, Command Injection),
 * static call-graph reachability proves it is unreachable from entry points,
 * so it should be prioritized lower than reachable vulnerabilities.
 */
'use strict';

const { exec } = require('child_process');

/**
 * VULNERABILITY: SQL Injection (CWE-89)
 * Reachability: UNREACHABLE from server.js
 */
function processBatchSql(dbConnection, rawBatchQuery, batchId) {
  // Vulnerable SQL concatenation
  const sql = "SELECT * FROM legacy_batch WHERE id = '" + batchId + "' AND data = " + rawBatchQuery;
  return dbConnection.query(sql);
}

/**
 * VULNERABILITY: Command Injection (CWE-78)
 * Reachability: UNREACHABLE from server.js
 */
function exportLegacyBackup(backupDestination, archiveName) {
  // Vulnerable shell command concatenation
  const cmd = "tar -czf " + backupDestination + "/" + archiveName + " /var/legacy_data";
  exec(cmd, (err, stdout) => {
    if (err) console.error("Backup failed", err);
  });
}

/**
 * VULNERABILITY: SQL Injection (CWE-89)
 * Reachability: UNREACHABLE from server.js
 */
function legacyAuth(username, passwordHash) {
  const query = "SELECT username, role FROM admin_users WHERE username = '" + username + "' AND hash = '" + passwordHash + "'";
  return query;
}

module.exports = { processBatchSql, exportLegacyBackup, legacyAuth };
