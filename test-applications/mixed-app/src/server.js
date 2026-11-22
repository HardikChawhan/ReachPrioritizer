/**
 * mixed-app/src/server.js
 * Application entry point for mixed test application.
 * Connects to active API routes, but does NOT connect legacy or archived modules.
 */
'use strict';

const http = require('http');
const { setupApiRoutes } = require('./routes/api');

function createApp() {
  const routes = {};
  return {
    get(path, handler) {
      routes[`GET ${path}`] = handler;
    },
    post(path, handler) {
      routes[`POST ${path}`] = handler;
    },
    handle(req, res) {
      const key = `${req.method} ${req.url.split('?')[0]}`;
      const handler = routes[key];
      if (handler) {
        handler(req, res);
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Not found' }));
      }
    },
    listen(port, callback) {
      const server = http.createServer((req, res) => this.handle(req, res));
      return server.listen(port, callback);
    }
  };
}

function startServer() {
  const app = createApp();
  // Register active API routes
  setupApiRoutes(app);
  
  // Notice: legacy/legacyProcessor.js and utils/archivedUtil.js are NEVER imported or wired up!
  
  const port = process.env.PORT || 3002;
  const server = app.listen(port, () => {
    console.log(`Mixed test application running on port ${port}`);
  });
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = { createApp, startServer };
