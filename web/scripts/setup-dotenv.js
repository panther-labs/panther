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

/**
 * Makes sure to load ENV vars from the corresponding dotenv file (based on a script param)
 */
const path = require('path');
const dotenv = require('dotenv');
const minimist = require('minimist');
const { spawn } = require('child_process');
const chalk = require('chalk');

const { environment, _: otherArgs } = minimist(process.argv.slice(2));
if (!environment) {
  throw new Error(
    chalk.red('No environment provided. Please add one through the "--environment" flag')
  );
}

dotenv.config({
  path: path.resolve(`web/config/.env.${environment}`),
});

if (otherArgs.length) {
  const [command, ...commandArgs] = otherArgs;
  spawn(command, commandArgs, { stdio: 'inherit' });
}
