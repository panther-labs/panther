/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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
const expressStaticGzip = require('express-static-gzip');
const path = require('path');

// construct a mini server
const app = express();

const getCacheControlForFile = filepath => {
  if (/favicon.*\.(png|svg|ico)/.test(filepath)) {
    return 'max-age=604800,public,stale-while-revalidate=604800';
  }

  if (/\.(.*\.js|svg|jpg)/.test(filepath)) {
    return 'max-age=31536000,public,immutable';
  }

  return 'no-cache';
};

const addHeaders = (req, res, next) => {
  res.header('X-Powered-by', 'N/A');
  res.header('X-XSS-Protection', '1; mode=block');
  res.header('X-Frame-Options', 'SAMEORIGIN');
  res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.header('X-Content-Type-Options', 'nosniff');
  res.header(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'self' *.amazonaws.com; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; base-uri 'self';form-action 'self'"
  );
  res.header('Referrer-Policy', 'no-referrer');
  res.header(
    'Feature-Policy',
    "accelerometer 'none'; ambient-light-sensor 'none'; autoplay 'none'; battery 'none'; camera 'none'; geolocation 'none'; magnetometer 'none'; microphone 'none'; payment 'none'; usb 'none'; midi 'none"
  );
  next();
};

app.use('*', addHeaders);

// allow static assets to be served from the /dist folder
app.use(
  expressStaticGzip(path.resolve(__dirname, '../dist'), {
    enableBrotli: true,
    orderPreference: ['br'],
    serveStatic: {
      // disable this package's cache control since we are going to provide our own logic
      cacheControl: false,
      // add cache-control logic
      setHeaders: (res, filepath) => {
        res.setHeader('Cache-Control', getCacheControlForFile(filepath));
      },
    },
  })
);

// Instantly reply to health checks from our ALB
app.get('/healthcheck', (req, res) => {
  res.sendStatus(200);
});

// Resolve all other requests to the index.html file
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../dist/index.html'));
});

// initialize server
const port = process.env.SERVER_PORT || '8080';
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
