// secure-app/src/utils/serialize.js
// SECURE implementations: JSON.parse instead of eval, prototype-safe merge
'use strict';

/**
 * SECURE: Uses JSON.parse instead of eval.
 * JSON.parse only parses data structures — it cannot execute arbitrary code.
 */
function parseUserData(data) {
  if (typeof data !== 'string') {
    return { error: 'Invalid data: must be a string' };
  }
  try {
    // SECURE: JSON.parse is data-only, cannot execute code
    const result = JSON.parse(data);
    return result;
  } catch (err) {
    return { error: 'Invalid JSON: ' + err.message };
  }
}

/**
 * SECURE: Prototype-pollution-safe object merge.
 * Filters out __proto__, constructor, and prototype keys before assignment.
 * Uses hasOwnProperty to avoid inherited enumerable properties.
 */
function mergeConfig(target, source) {
  if (typeof source !== 'object' || source === null) return target;

  const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

  for (const key of Object.keys(source)) {
    // SECURE: skip dangerous prototype keys
    if (BLOCKED_KEYS.has(key)) {
      console.log('[SECURE] Prototype pollution attempt blocked for key:', key);
      continue;
    }
    // SECURE: use hasOwnProperty to avoid inherited properties
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      target[key] = source[key];
    }
  }
  return target;
}

const _defaultConfig = {};
mergeConfig(_defaultConfig, { timeout: 30, retries: 3 });

module.exports = { parseUserData, mergeConfig };
