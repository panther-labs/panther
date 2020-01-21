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
/* eslint-disable global-require, import/no-dynamic-require */

const fs = require('fs');
const chalk = require('chalk');

const ENTERPRISE_WEBPACK_CONFIG = './enterprise/web/webpack.config.js';
const PUBLIC_WEBPACK_CONFIG = './web/webpack.config.js';

const requiredEnv = [
  'AWS_ACCOUNT_ID',
  'AWS_REGION',
  'WEB_APPLICATION_GRAPHQL_API_ENDPOINT',
  'WEB_APPLICATION_USER_POOL_CLIENT_ID',
  'WEB_APPLICATION_USER_POOL_ID',
];

const unsetVars = requiredEnv.filter(env => process.env[env] === undefined);
if (unsetVars.length) {
  throw new Error(chalk.red(`Couldn't find the following ENV vars: ${unsetVars.join(', ')}`));
}

if (fs.existsSync(ENTERPRISE_WEBPACK_CONFIG)) {
  module.exports = require(ENTERPRISE_WEBPACK_CONFIG);
} else {
  module.exports = require(PUBLIC_WEBPACK_CONFIG);
}
