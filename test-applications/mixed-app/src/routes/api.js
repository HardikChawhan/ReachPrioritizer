/**
 * mixed-app/src/routes/api.js
 * Active route definitions wired to server.js
 */
'use strict';

const { handleProcess, handleStats } = require('../controllers/apiController');

function setupApiRoutes(app) {
  // GET /api/process - delegates to controller
  app.get('/api/process', function processRouteHandler(req, res) {
    handleProcess(req, res);
  });

  // GET /api/stats - delegates to controller
  app.get('/api/stats', function statsRouteHandler(req, res) {
    handleStats(req, res);
  });
}

module.exports = { setupApiRoutes };
