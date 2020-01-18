/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* eslint-disable no-console  */
const express = require('express');
const path = require('path');

// construct a mini server
const app = express();

// allow static assets to be served from the /dist folder
app.use(express.static(path.join(path.resolve(), 'web/dist')));

// Instantly reply to health checks from our ALB
app.get('/healthcheck', (req, res) => {
  res.sendStatus(200);
});

// Resolve all other requests to the index.html file
app.get('*', (req, res) => {
  res.sendFile(path.join(path.resolve(), 'web/dist/index.html'));
});

// initialize server
app.listen(process.env.SERVER_PORT, () => {
  console.log(`Listening on port ${process.env.SERVER_PORT}`);
});
