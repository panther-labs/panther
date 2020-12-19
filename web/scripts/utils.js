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

const dotenv = require('dotenv');
const chalk = require('chalk');
const fs = require('fs');

function overrideDotEnvVars(path) {
  const envConfig = dotenv.parse(fs.readFileSync(path));
  // eslint-disable-next-line
  for (const k in envConfig) {
    process.env[k] = envConfig[k];
  }
}

function loadDotEnvVars(path) {
  const dotenvResult = dotenv.config({ path });
  if (dotenvResult.error) {
    throw new Error(chalk.red(dotenvResult.error));
  }
}

function getAppTemplateParams() {
  const PANTHER_CONFIG = {
    AWS_REGION: process.env.AWS_REGION,
    AWS_ACCOUNT_ID: process.env.AWS_ACCOUNT_ID,
    NODE_ENV: process.env.NODE_ENV,
    WEB_APPLICATION_GRAPHQL_API_ENDPOINT: process.env.WEB_APPLICATION_GRAPHQL_API_ENDPOINT,
    WEB_APPLICATION_USER_POOL_CLIENT_ID: process.env.WEB_APPLICATION_USER_POOL_CLIENT_ID,
    WEB_APPLICATION_USER_POOL_ID: process.env.WEB_APPLICATION_USER_POOL_ID,
    PANTHER_COMMIT: process.env.PANTHER_COMMIT,
    PANTHER_VERSION: process.env.PANTHER_VERSION,
  };

  const missingKeys = Object.keys(PANTHER_CONFIG).filter(key => PANTHER_CONFIG[key] === undefined);
  if (missingKeys.length) {
    throw new Error(chalk.red(`Couldn't find the following ENV vars: ${missingKeys.join(', ')}`));
  }

  return { PANTHER_CONFIG };
}

const getCacheControlForFileType = filepath => {
  if (/favicon.*\.(png|svg|ico)/.test(filepath)) {
    return 'max-age=604800,public,stale-while-revalidate=604800';
  }

  if (/\.(.*\.js|svg|jpg)/.test(filepath)) {
    return 'max-age=31536000,public,immutable';
  }

  return 'no-cache';
};

module.exports = {
  overrideDotEnvVars,
  loadDotEnvVars,
  getAppTemplateParams,
  getCacheControlForFileType,
};
