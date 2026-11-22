'use strict';
const express = require('express');
const { downloadFile, convertImage, proxyRequest } = require('../controllers/fileController');

const router = express.Router();

router.get('/download', downloadFile);
router.post('/convert', convertImage);
router.get('/proxy', proxyRequest);

// VULNERABLE (CWE-601): open redirect
router.get('/go', function goHandler(req, res) {
  res.redirect(req.query.next);
});

module.exports = router;
