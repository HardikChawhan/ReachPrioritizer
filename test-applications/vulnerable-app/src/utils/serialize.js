// vulnerable-app/src/utils/serialize.js
// CWE-94: Code Injection via eval, CWE-1321: Prototype Pollution
'use strict';

/**
 * VULNERABLE: Code Injection (CWE-94)
 * Passes raw user data to eval(), allowing arbitrary JS execution.
 * Attacker can inject: data = "process.exit(1)" or malicious payload.
 */
function parseUserData(data) {
  // VULNERABLE: eval executes arbitrary JavaScript
  console.log('[VULN] Evaluating user data via eval()');
  try {
    const result = eval(data); // eslint-disable-line no-eval
    return result;
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * VULNERABLE: Prototype Pollution (CWE-1321)
 * Copies all keys from source to target without filtering __proto__.
 * Attacker can set: source = {"__proto__": {"isAdmin": true}}
 * This pollutes Object.prototype for all objects in the process.
 *
 * NOTE: This function is called only from internal setup, NOT from HTTP routes.
 * Ground truth: reachable = false
 */
function mergeConfig(target, source) {
  if (typeof source !== 'object' || source === null) return target;
  // VULNERABLE: does not filter __proto__ or constructor keys
  for (const key in source) {
    // No hasOwnProperty check, no prototype key filter
    target[key] = source[key];
  }
  return target;
}

// Internal setup call - not exposed via any HTTP route
const _defaultConfig = {};
mergeConfig(_defaultConfig, { timeout: 30, retries: 3 });

module.exports = { parseUserData, mergeConfig };
