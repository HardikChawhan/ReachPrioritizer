/**
 * mixed-app/src/utils/archivedUtil.js
 * Unused archive utility.
 * Security status: SECURE / BENIGN (not vulnerable)
 * Reachability: UNREACHABLE (dead code, not imported)
 */
'use strict';

/**
 * SECURE: Non-vulnerable formatting logic
 * Reachability: UNREACHABLE from server.js
 */
function oldFormat(value) {
  return String(value).toUpperCase();
}

/**
 * SECURE: Inactive archive helper
 * Reachability: UNREACHABLE from server.js
 */
function archiveLegacyData(payload) {
  try {
    const serialized = JSON.stringify(payload);
    return Buffer.from(serialized).toString('base64');
  } catch (e) {
    return null;
  }
}

module.exports = { oldFormat, archiveLegacyData };
