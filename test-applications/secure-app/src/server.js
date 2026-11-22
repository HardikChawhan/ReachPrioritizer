// secure-app/src/server.js
// Entry point for the secure test application (same functionality, secure implementation)
'use strict';

const http = require('http');
const { setupUserRoutes } = require('./routes/users');
const { setupFileRoutes } = require('./routes/files');

const app = {
  _routes: [],
  get(path, handler) {
    this._routes.push({ method: 'GET', path, handler });
  },
  post(path, handler) {
    this._routes.push({ method: 'POST', path, handler });
  }
};

setupUserRoutes(app);
setupFileRoutes(app);

const PORT = 3002;
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const method = req.method;
  const pathname = url.pathname;

  for (const route of app._routes) {
    if (route.method !== method) continue;

    const routeParts = route.path.split('/');
    const reqParts = pathname.split('/');
    if (routeParts.length !== reqParts.length) continue;

    const params = {};
    let matched = true;
    for (let i = 0; i < routeParts.length; i++) {
      if (routeParts[i].startsWith(':')) {
        params[routeParts[i].slice(1)] = reqParts[i];
      } else if (routeParts[i] !== reqParts[i]) {
        matched = false;
        break;
      }
    }

    if (matched) {
      const fakeReq = {
        params,
        query: Object.fromEntries(url.searchParams),
        body: {}
      };
      const fakeRes = {
        json(data) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(data));
        },
        status(code) {
          res.statusCode = code;
          return this;
        },
        send(data) {
          res.writeHead(res.statusCode || 200);
          res.end(String(data));
        }
      };
      route.handler(fakeReq, fakeRes);
      return;
    }
  }

  res.writeHead(404);
  res.end('Not Found');
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`secure-app listening on port ${PORT}`);
  });
}

module.exports = { app, server };
