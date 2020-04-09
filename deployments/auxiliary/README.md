# Panther's Auxiliary Deployment Files

A collection of templates used to create auxiliary infrastructure in support of a Panther deployment.

We refer to the AWS account where Panther itself is deployed as the _master_ account.
Accounts which Panther scans or pulls log data from are called _satellite_ accounts. An account can
function as both - in fact, by default, Panther onboards its own account for cloud security and log analysis.

These templates are primarily for _satellite_ accounts.
For example, [panther-cloudsec-iam](cloudformation/panther-cloudsec-iam.yml) creates IAM roles
which Panther Cloud Security can assume to scan your AWS account.

Each template is provided in [CloudFormation](cloudformation) and [Terraform](terraform) formats -
choose whichever works best for your workflow.
