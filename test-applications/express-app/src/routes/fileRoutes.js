'use strict';
const express = require('express');
const _ = require('lodash');
const { downloadFile, convertImage, proxyRequest } = require('../controllers/fileController');

const router = express.Router();

router.get('/download', downloadFile);
router.post('/convert', convertImage);
router.get('/proxy', proxyRequest);

// VULNERABLE (CWE-601): open redirect
router.get('/go', function goHandler(req, res) {
  res.redirect(req.query.next);
});

// VULNERABLE DEPENDENCY: lodash 4.17.4 _.template() is affected by CVE-2021-23337
// (command injection through the template string) and is called with request data
router.post('/render', function renderTemplate(req, res) {
  const compiled = _.template(req.body.template);
  res.json({ html: compiled({ user: 'guest' }) });
});

module.exports = router;
