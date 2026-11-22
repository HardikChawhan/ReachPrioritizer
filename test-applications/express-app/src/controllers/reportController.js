'use strict';
// DEAD CODE: no router references this controller
const { exec } = require('child_process');

// VULNERABLE (CWE-78) but UNREACHABLE
exports.generateReport = (req, res) => {
  exec(`wkhtmltopdf ${req.query.page} /tmp/report.pdf`, () => res.end('ok'));
};
