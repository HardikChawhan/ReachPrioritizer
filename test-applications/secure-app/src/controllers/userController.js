// secure-app/src/controllers/userController.js
// SECURE implementations using parameterized queries
'use strict';

/**
 * SECURE: Uses parameterized query placeholder to prevent SQL Injection.
 * The user-supplied id is passed as a bound parameter, never concatenated.
 */
function getUserById(id) {
  // SECURE: parameterized query - id is bound, not concatenated
  const sql = 'SELECT * FROM users WHERE id = ?';
  const params = [id];
  console.log('[SECURE] Executing parameterized query:', sql, params);
  // Simulated DB call: db.query(sql, params)
  return { query: sql, params, rows: [] };
}

/**
 * SECURE: Both username and password are passed as bound parameters.
 * No string concatenation into the SQL string.
 */
function authenticateUser(username, password) {
  // SECURE: parameterized query prevents injection regardless of input values
  const sql = 'SELECT * FROM users WHERE username = ? AND password_hash = ?';
  const params = [username, password];
  console.log('[SECURE] Executing parameterized query:', sql, params);
  // Simulated: db.query(sql, params)
  return false; // Simulated auth result
}

/**
 * SECURE: Search term is passed as a bound parameter with LIKE placeholder.
 * SQL wildcards are part of the parameter, not the query template.
 */
function searchUsers(query) {
  // SECURE: parameterized LIKE query - wildcards in the param, not the SQL template
  const sql = 'SELECT * FROM users WHERE name LIKE ?';
  const params = ['%' + (query || '') + '%'];
  console.log('[SECURE] Executing parameterized query:', sql, params);
  // Simulated: db.query(sql, params)
  return { query: sql, params, rows: [] };
}

module.exports = { getUserById, authenticateUser, searchUsers };
