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

const core = require('@actions/core');
const github = require('@actions/github');
const { execSync } = require('child_process');

const PR_TITLE_PREFIX = '[Sync]';
const BRANCH_PREFIX = 'sync-';

/**
 * @param str a "local" branch name
 * @returns {string} the branch name with the proper prefix
 */
const getPrBranch = str => `${BRANCH_PREFIX}${str}`;

/**
 * @param str the original PR title
 * @returns {string} the synced PR's title
 */
const getPrTitle = str => `${PR_TITLE_PREFIX} ${str}`;

const main = async () => {
  try {
    const destRepo = core.getInput('destRepo');
    const destBranch = core.getInput('destBranch');
    const ignoreLabel = core.getInput('ignoreLabel');
    const token = core.getInput('token');

    // Get the JSON webhook payload for the event that triggered the workflow
    const srcPullRequest = github.context.payload.pull_request;

    // If PR was closed, but it was not due to it being merged, then do nothing
    if (!srcPullRequest.merged) {
      core.setOutput('message', 'PR was closed without merging. Terminating...');
      return;
    }

    // If PR has the "ignore" label, then the PR sync should not happen
    core.debug('PR was closed due to a merge. Looking for ignore labels...');
    const shouldIgnore = srcPullRequest.labels.some(label => label.name === ignoreLabel);
    if (shouldIgnore) {
      core.setOutput('message', 'PR contained an ignore label. Terminating...');
      return;
    }

    core.debug('An ignore label was not found. Starting sync process...');
    const destPullRequestBranchName = getPrBranch(srcPullRequest.head.ref);

    core.debug('Creating a branch from the merge commit...');
    execSync(`git checkout -b ${destPullRequestBranchName}`);
    execSync(`git remote add target https://github.com/${destRepo}.git`); // prettier-ignore
    execSync(`git push target ${destPullRequestBranchName}`);

    // https://developer.github.com/v3/pulls/#create-a-pull-request
    core.debug('Creating a pull request...');
    const octokit = github.getOctokit(token);
    const { data: destPullRequest } = await octokit.request(`POST /repos/${destRepo}/pulls`, {
      title: getPrTitle(srcPullRequest.title),
      body: srcPullRequest.body,
      maintainer_can_modify: true,
      head: destPullRequestBranchName,
      base: destBranch,
      draft: false,
    });

    // https://developer.github.com/v3/issues/#update-an-issue
    core.debug('Setting assignees, labels & milestone...');
    try {
      await octokit.request(`PATCH /repos/${destRepo}/issues/${destPullRequest.number}`, {
        assignees: srcPullRequest.assignees.map(assignee => assignee.login),
        labels: srcPullRequest.labels.map(label => label.name),
        milestone: srcPullRequest.milestone ? srcPullRequest.milestone.number : null,
      });
    } catch (error) {
      core.debug(error.message);
    }

    // https://developer.github.com/v3/pulls/review_requests/#request-reviewers-for-a-pull-request
    core.debug('Setting reviewers...');
    try {
      await octokit.request(
        `POST /repos/${destRepo}/pulls/${destPullRequest.number}/requested_reviewers`,
        {
          reviewers: [srcPullRequest.user.login],
        }
      );
    } catch (error) {
      core.debug(error.message);
    }

    // Set the `url` output to the created PR's URL
    core.setOutput('url', destPullRequest.url);
    core.setOutput('message', 'Successfully synced PRs');
  } catch (error) {
    core.setFailed(error);
  } finally {
    // noop
  }
};

main();
