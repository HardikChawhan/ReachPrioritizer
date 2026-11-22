'use strict';

// VULNERABLE (CWE-1321): recursive merge without blocking __proto__ / constructor
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// SECURE (and unused): blocks dangerous keys
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (!['theme', 'language', 'timezone'].includes(key)) continue;
    target[key] = source[key];
  }
  return target;
}

module.exports = { deepMerge, safeMerge };
