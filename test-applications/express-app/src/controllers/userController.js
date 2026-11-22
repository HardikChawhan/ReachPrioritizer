'use strict';
const path = require('path');
const db = require('../db');
const config = require('../config');
const UserService = require('../services/userService');
const { deepMerge } = require('../utils/merge');

const service = new UserService(db);

module.exports = {
  // SECURE: parameterized lookup inside UserService.findById
  async getUser(req, res) {
    const user = await service.findById(req.params.id);
    res.json(user);
  },

  // VULNERABLE (CWE-89) via UserService.search
  async searchUsers(req, res) {
    const term = req.body.term;
    const rows = await service.search(term);
    res.json(rows);
  },

  // VULNERABLE (CWE-1321) via utils/merge.deepMerge
  updateSettings(req, res) {
    const settings = {};
    deepMerge(settings, req.body);
    res.json(settings);
  },

  // SECURE: path.basename strips directory components
  getAvatar(req, res) {
    const fileName = path.basename(req.query.name);
    res.sendFile(path.join(config.avatarDir, fileName));
  },
};
