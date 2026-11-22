'use strict';
const express = require('express');
const ctrl = require('../controllers/userController');

const router = express.Router();

router.get('/:id', ctrl.getUser);
router.post('/search', ctrl.searchUsers);
router.post('/settings', ctrl.updateSettings);
router.get('/avatar', ctrl.getAvatar);

// VULNERABLE (CWE-79): reflected XSS in an inline handler
router.get('/greet', (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

// SECURE: escaped output
router.get('/greet-safe', (req, res) => {
  res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`);
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

module.exports = router;
