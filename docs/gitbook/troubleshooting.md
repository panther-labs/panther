# Troubleshooting Panther

This section acts as a quick Q&A on issues that you may face during your Panther deployment.

## Deployment Time-Out

Don't worry. You can safely re-deploy Panther by running `mage deploy` and it will pick up where it left off.

Alternatively, if you 're using temporary credentials, please add a longer timeout.

## Deployment Failed

`open deployments/bootstrap.yml: no such file or directory`

This is an issue with Docker and the way volumes work.

To resolve that, please step close the container (Ctrl+D on Mac) and reconnect to it by typing `./dev.sh` so that the container can pick up all the necessary files.

Running `mage deploy` should resolve the issue.

## Mistyped Email During `mage deploy`

Don't worry, these things happen!

Simply go to Cognito and create a new user by specifying all the necessary fields.
