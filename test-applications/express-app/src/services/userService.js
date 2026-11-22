'use strict';

class UserService {
  constructor(db) {
    this.db = db;
  }

  // SECURE: parameterized query
  findById(id) {
    return this.db.query('SELECT id, name FROM users WHERE id = ?', [id]);
  }

  // VULNERABLE (CWE-89): template literal SQL
  search(term) {
    const sql = `SELECT id, name FROM users WHERE name LIKE '%${term}%'`;
    return this.db.query(sql);
  }
}

module.exports = UserService;
