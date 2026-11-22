'use strict';
const express = require('express');
const config = require('./config');
const userRoutes = require('./routes/userRoutes');
const fileRoutes = require('./routes/fileRoutes');
const { startCleanupJob } = require('./jobs/cleanup');

const app = express();
app.use(express.json());
app.use('/api/users', userRoutes);
app.use('/api/files', fileRoutes);

// NOTE: routes/adminRoutes.js and controllers/reportController.js are never mounted.

startCleanupJob();

app.listen(config.port, () => {
  console.log(`express-app listening on ${config.port}`);
});

module.exports = app;
