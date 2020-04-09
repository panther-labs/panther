/**
 * A Cloud-Native SIEM for the Modern Security Team
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

const { execSync } = require('child_process');
const dotenv = require('dotenv');
const chalk = require('chalk');

function loadDotEnvVars(path) {
  const dotenvResult = dotenv.config({ path });
  if (dotenvResult.error) {
    throw new Error(chalk.red(dotenvResult.error));
  }
}

function getPantherDeploymentVersion() {
  try {
    return execSync('git describe --tags')
      .toString()
      .trim();
  } catch (err) {
    throw new Error(chalk.red(err.message));
  }
}

function validateRequiredEnv() {
  const requiredEnvs = [
    'AWS_ACCOUNT_ID',
    'AWS_REGION',
    'WEB_APPLICATION_GRAPHQL_API_ENDPOINT',
    'WEB_APPLICATION_USER_POOL_CLIENT_ID',
    'WEB_APPLICATION_USER_POOL_ID',
  ];

  const unsetVars = requiredEnvs.filter(env => process.env[env] === undefined);
  if (unsetVars.length) {
    throw new Error(chalk.red(`Couldn't find the following ENV vars: ${unsetVars.join(', ')}`));
  }

  return true;
}

module.exports = { loadDotEnvVars, getPantherDeploymentVersion, validateRequiredEnv };
