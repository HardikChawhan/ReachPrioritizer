// secure-app/src/routes/users.js
'use strict';

const { getUserById, authenticateUser, searchUsers } = require('../controllers/userController');
const { parseUserData } = require('../utils/serialize');

function getUser(req, res) {
  const id = req.params.id;
  const result = getUserById(id);
  res.json({ user: result });
}

function login(req, res) {
  const { username, password } = req.body;
  const result = authenticateUser(username, password);
  res.json({ success: result });
}

function search(req, res) {
  const query = req.query.q;
  const results = searchUsers(query);
  res.json({ results });
}

function parseData(req, res) {
  const data = req.query.data;
  const result = parseUserData(data);
  res.json({ result });
}

function setupUserRoutes(app) {
  app.get('/users/:id', getUser);
  app.post('/login', login);
  app.get('/search', search);
  app.get('/parse', parseData);
}

module.exports = { setupUserRoutes };
