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

const PR_TITLE_PREFIX = '[Sync]';

const main = async () => {
  try {
    const repo = core.getInput('repo');
    const head = core.getInput('head');
    const base = core.getInput('base');
    const token = core.getInput('token');

    // Get the JSON webhook payload for the event that triggered the workflow
    const srcPullRequest = github.context.payload.pull_request;

    // https://developer.github.com/v3/pulls/#create-a-pull-request
    core.debug('Creating a pull request...');
    const octokit = github.getOctokit(token);
    const { data: destPullRequest } = await octokit.request(`POST /repos/${repo}/pulls`, {
      title: PR_TITLE_PREFIX + srcPullRequest.title,
      body: srcPullRequest.body.replace(/ (#[0-9]+ )/g, ` ${srcPullRequest.head.repo.full_name}$1`),
      maintainer_can_modify: true,
      head,
      base,
      draft: false,
    });

    // https://developer.github.com/v3/issues/#update-an-issue
    core.debug('Setting assignees, labels & milestone...');
    try {
      let milestoneId;
      if (srcPullRequest.milestone) {
        const { data: destMilestones } = await octokit.request(`GET /repos/${repo}/milestones`);
        const matchingMilestone = destMilestones.find(
          milestone => milestone.title === srcPullRequest.milestone.title
        );
        milestoneId = matchingMilestone ? matchingMilestone.number : null;
      }

      await octokit.request(`PATCH /repos/${repo}/issues/${destPullRequest.number}`, {
        assignees: srcPullRequest.assignees.map(assignee => assignee.login),
        labels: srcPullRequest.labels.map(label => label.name),
        milestone: milestoneId,
      });
    } catch (error) {
      core.debug(error.message);
    }

    // https://developer.github.com/v3/pulls/review_requests/#request-reviewers-for-a-pull-request
    core.debug('Setting reviewers...');
    try {
      await octokit.request(
        `POST /repos/${repo}/pulls/${destPullRequest.number}/requested_reviewers`,
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
