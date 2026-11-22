// vulnerable-app/src/controllers/userController.js
// CWE-89: SQL Injection via string concatenation
'use strict';

/**
 * VULNERABLE: SQL Injection (CWE-89)
 * Builds SQL query by directly concatenating unsanitized user input.
 * Attacker can inject: id = "1 OR 1=1" to dump all users.
 */
function getUserById(id) {
  const sql = 'SELECT * FROM users WHERE id = ' + id;
  // Simulate DB execution (no real DB in test app)
  console.log('[VULN] Executing query:', sql);
  return { query: sql, rows: [] };
}

/**
 * VULNERABLE: SQL Injection (CWE-89)
 * Both username and password are concatenated directly into SQL.
 * Attacker can bypass auth with: username = "admin'--"
 */
function authenticateUser(username, password) {
  const sql = "SELECT * FROM users WHERE username = '" + username +
              "' AND password = '" + password + "'";
  console.log('[VULN] Executing query:', sql);
  return sql.length > 0; // simulated check
}

/**
 * VULNERABLE: SQL Injection (CWE-89)
 * Search query is embedded directly in LIKE clause without escaping.
 * Attacker can inject: query = "' UNION SELECT * FROM secrets--"
 */
function searchUsers(query) {
  const sql = "SELECT * FROM users WHERE name LIKE '%" + query + "%'";
  console.log('[VULN] Executing query:', sql);
  return { query: sql, rows: [] };
}

module.exports = { getUserById, authenticateUser, searchUsers };
