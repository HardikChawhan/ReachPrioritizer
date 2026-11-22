'use strict';
// VULNERABLE (CWE-798): hardcoded signing secret — executed at startup, not attacker-reachable
const JWT_SECRET = 'sup3r-s3cret-signing-key-2024';

module.exports = {
  port: process.env.PORT || 3005,
  jwtSecret: JWT_SECRET,
  uploadDir: '/srv/uploads',
  avatarDir: '/srv/avatars',
};
