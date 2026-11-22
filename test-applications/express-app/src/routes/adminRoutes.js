'use strict';
// DEAD CODE: this router is never required or mounted by app.js
const express = require('express');
const router = express.Router();

// VULNERABLE (CWE-94) but UNREACHABLE: eval of request body
router.post('/eval', function adminEval(req, res) {
  const result = eval(req.body.code);
  res.json({ result });
});

module.exports = router;
