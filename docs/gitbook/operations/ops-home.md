# Background

Panther has 5 CloudWatch dashboards to provide visibility in the operation of the system:

- PantherOverview: An overview all errors and performance of all Panther components.
- PantherInfrastructure: Details of the components monitoring infrastructure for CloudSecurity.
- PantherAlertProcessing: Detail of the components that relay alerts for CloudSecurity and Log Processing.
- PantherLogProcessing: Detail of the components processing logs and running rules.
- PantherRemediation: Detail of the components that remediate infrastructure issues.

Panther uses CloudWatch Alarms to monitor the health of each component. Edit the `deployments/panther_config.yml`
file to associate an SNS topic you have created with the Panther CloudWatch alarms to receive notifications. If this value is
blank then Panther will associate alarms with the default Panther SNS topic called `panther-alarms`:

```yaml
MonitoringParameterValues:
  # This is the arn for the SNS topic you want associated with Panther system alarms.
  # If this is not set alarms will be associated with the SNS topic `panther-alarms`.
  AlarmSNSTopicARN: 'arn:aws:sns:us-east-1:05060362XXX:MyAlarmSNSTopic'
```

To configure alarms to send to your team, follow the guides below:

- [PagerDuty Integration](https://support.pagerduty.com/docs/aws-cloudwatch-integration-guide)
