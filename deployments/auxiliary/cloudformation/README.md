# Panther's CloudFormation Templates

A collection of CloudFormation templates to configure auxiliary Panther infrastructure. These templates are also available in a public S3 bucket for your convenience:

`https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/TEMPLATE-NAME/VERSION/template.yml`

VERSION can be `latest` or a specific Panther version number.

## Makefile

Panther team members can upload templates with the provided `Makefile`:

```
make upload-single template=panther-deployment-role.yml
make upload-all
```
