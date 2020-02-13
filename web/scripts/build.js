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

const { spawn } = require('child_process');
const { loadDotEnvVars, getPantherDeploymentVersion } = require('./utils');

// Mark the Node environment as production in order to load the webpack configuration
process.env.NODE_ENV = 'production';
// Generate  a `PANTHER_VERSION` that the javascript error logging function running in the browser
// is going to reference when reporting a crash
process.env.PANTHER_VERSION = getPantherDeploymentVersion();

// Add all the sentry-related ENV vars to process.env
loadDotEnvVars('web/.env.sentry');

// Add all the aws-related ENV vars to process.env
loadDotEnvVars('out/.env.aws');

spawn('node_modules/.bin/webpack', { stdio: 'inherit' });
