# Troubleshooting Panther

This section is a resource for issues you may face during your Panther deployment and usage.

## Deployment

### Time-Outs

Don't worry. You can safely re-deploy Panther by running `mage deploy` and it will pick up where it left off.

Alternatively, if you're using temporary credentials, please add a longer timeout.

### Mistyped Email

Don't worry, these things happen! From the AWS console in the deployed region:

1. Go to the AWS Cognito Console and click Manage User Pools
2. Click on the incorrect user
3. Disable, then delete the user

Then just run `mage deploy` to setup the first user again.

## Cloud Security

### My Resources Haven't Updated

When configuring Cloud Security for a given account, the default scan interval is 24h.

To reduce this interval, onboard CloudTrail data from the given account, or configure real-time events.
