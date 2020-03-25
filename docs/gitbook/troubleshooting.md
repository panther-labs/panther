# Troubleshooting Panther

This section acts as a quick Q&A on issues that you may face during your Panther deployment.

## Deployment Time-Out

Don't worry. You can safely re-deploy Panther by running `mage deploy` and it will pick up where it left off.

Alternatively, if you're using temporary credentials, please add a longer timeout.

## Mistyped Email During `mage deploy`

Don't worry, these things happen! From the AWS console in the deployed region:

1. Go to Cognito => Manage User Pools
2. Click on the incorrect user
3. Disable then delete the user

Then just run `mage deploy` to setup the first user again.
