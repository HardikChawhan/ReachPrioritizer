'use strict';
// Minimal DB facade (no real database in the test application)
const db = {
  query(sql, params) {
    return Promise.resolve({ sql, params, rows: [] });
  },
};
module.exports = db;
