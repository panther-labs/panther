const core = require('@actions/core');
const github = require('@actions/github');

try {
  const destRepo = core.getInput('destRepo');

  core.setOutput('url', `https://github.com/${destRepo}`);
  // Get the JSON webhook payload for the event that triggered the workflow
  const payload = JSON.stringify(github.context.payload, undefined, 2);
  // eslint-disable-next-line no-console
  console.log(`The event payload: ${payload}`);
} catch (error) {
  core.setFailed(error.message);
}
