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

/* eslint-disable no-console */
const SentryCli = require('@sentry/cli');
const chalk = require('chalk');
const { configureSentryEnvVars, getPantherDeploymentVersion } = require('./utils');

/**
 * Uploads to Sentry the source maps that were generated by our build step
 *
 * @param releaseName An ID for the groups of source maps that are going to be uploaded to Sentry
 */
const uploadSourceMapsToSentry = async releaseName => {
  if (!releaseName) {
    throw new Error(
      chalk.red("Could't find Sentry release name. Please set the ENV var `PANTHER_VERSION`")
    );
  }

  const cli = new SentryCli();
  try {
    console.log(chalk.cyan('Creating new Sentry release: ', chalk.underline(releaseName)));
    await cli.releases.new(releaseName);

    console.log(chalk.cyan('Uploading source maps for release'));
    await cli.releases.uploadSourceMaps(releaseName, {
      include: ['web/dist'],
      // rewrite: false,
    });

    console.log(chalk.cyan('Finalizing release'));
    await cli.releases.finalize(releaseName);

    console.log(chalk.green('Source maps uploaded successfully'));
  } catch (e) {
    console.log(chalk.red(`Source maps uploading failed: ${e}`));
  }
};

// Add all the sentry-related vars to process.env
configureSentryEnvVars();

uploadSourceMapsToSentry(getPantherDeploymentVersion());
