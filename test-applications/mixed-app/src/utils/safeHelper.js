/**
 * mixed-app/src/utils/safeHelper.js
 * Secure helper utilities.
 * REACHABLE from server.js -> api.js -> apiController.js -> safeHelper.js
 * Security status: SECURE / BENIGN (not vulnerable)
 */
'use strict';

/**
 * SECURE: Safely encodes string output
 * Reachability: REACHABLE
 */
function formatOutput(rawString) {
  if (typeof rawString !== 'string') return '';
  return rawString
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * SECURE: Computes safe static system telemetry
 * Reachability: REACHABLE
 */
function computeSystemStats() {
  const uptime = process.uptime();
  const mem = process.memoryUsage();
  return {
    uptimeSeconds: Math.floor(uptime),
    heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
    status: 'healthy'
  };
}

/**
 * SECURE: Input validation and sanitization
 * Reachability: REACHABLE
 */
function sanitizeString(input, maxLength = 256) {
  if (!input || typeof input !== 'string') return '';
  return input.trim().slice(0, maxLength);
}

module.exports = { formatOutput, computeSystemStats, sanitizeString };
