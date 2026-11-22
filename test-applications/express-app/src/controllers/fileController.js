'use strict';
const path = require('path');
const axios = require('axios');
const { execFile } = require('child_process');
const config = require('../config');

// VULNERABLE (CWE-22): user-controlled path joined without validation
exports.downloadFile = (req, res) => {
  const target = path.join(config.uploadDir, req.query.file);
  res.download(target);
};

// SECURE: execFile without a shell and a constant executable
exports.convertImage = (req, res) => {
  execFile('convert', [req.body.input, 'out.png'], (err) => {
    res.json({ ok: !err });
  });
};

// VULNERABLE (CWE-918): server-side request forgery
exports.proxyRequest = async (req, res) => {
  const response = await axios.get(req.query.url);
  res.json(response.data);
};
