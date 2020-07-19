const core = require('@actions/core');
const github = require('@actions/github');

const PR_TITLE_PREFIX = '[OSS Sync]';
const MASTER_BRANCH = 'v1.0.1-docs';

const main = async () => {
  try {
    core.debug('Initializing...');
    const destRepo = core.getInput('destRepo');
    const ignoreLabel = core.getInput('ignoreLabel');
    const token = core.getInput('token');

    // Get the JSON webhook payload for the event that triggered the workflow
    const { pull_request: pullRequest } = github.context.payload;

    // If PR was closed, but it was not due to it being merged, then do nothing
    if (!pullRequest.merged) {
      return;
    }
    core.debug('PR was closed due to a merge. Looking for ignore labels...');

    // If PR has the "ignore" label, then the PR sync should not happen
    const isBackport = pullRequest.labels.some(label => label.name === ignoreLabel);
    if (isBackport) {
      return;
    }
    core.debug('PR did not have an ignore label. Starting sync process...');

    core.debug('Initializing octokit...');
    const octokit = github.getOctokit(token);
    core.debug('Octokit instance setup successfully');

    // https://developer.github.com/v3/git/refs/#create-a-reference
    const prBranchName = pullRequest.head.ref;
    await octokit.request(`POST /repos/${destRepo}/git/refs`, {
      ref: `refs/heads/${prBranchName}`,
      sha: pullRequest.merge_commit_sha,
    });

    core.debug('Creating a pull request...');
    const destPullRequest = await octokit.request(`POST /repos/${destRepo}/pulls`, {
      title: `${PR_TITLE_PREFIX} ${pullRequest.title}`,
      body: pullRequest.body,
      maintainer_can_modify: true,
      head: prBranchName,
      base: MASTER_BRANCH,
      draft: false,
    });

    // Clone the existing labels
    core.debug(destPullRequest);

    // https://developer.github.com/v3/issues/#update-an-issue
    core.debug('Setting assignees, labels & milestone...');
    await octokit.request(
      `POST /repos/${destRepo}/pulls/repos/${destRepo}/issues/${destPullRequest.id}`,
      {
        assignees: pullRequest.assignees.map(assignee => assignee.login),
        labels: pullRequest.labels.map(label => label.name),
        milestone: pullRequest.milestone.id,
      }
    );

    // TODO: add reviewer

    // Set the `url` output to the created PR's URL
    core.setOutput('url', destPullRequest.url);
  } catch (error) {
    core.setFailed(error.message);
  } finally {
    // noop
  }
};

main();
