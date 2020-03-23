# Supported Logs

Panther analyzes different types of data generated from clouds, endpoints, network devices, or applications. All log data is parsed, analyzed, and then saved into the Panther data warehouse in your AWS account.

To request support for new log types, please open a [Github issue](https://github.com/panther-labs/panther/issues) or develop your own [with our guide](writing-parsers.md)!

## Log Categories

An effective monitoring strategy is applied in layers going from most broad to most specific:

1. Cloud
  1. [AWS](log-analysis/supported-logs/aws) (CloudTrail, S3 Access, AuroraMySQL, GuardDuty)
2. Network
  1. [AWS VPC Flow Logs](log-analysis/supported-logs/aws#aws-vpcflow)
  2. [AWS ALB](log-analysis/supported-logs/aws#aws-alb)
  3. _Suricata (coming soon!)_
  4. _Zeek (coming soon!)_
2. Host
  1. [Osquery](log-analysis/supported-logs/osquery)
  2. [OSSEC EventInfo](log-analysis/supported-logs/ossec)
  3. [Syslog](log-analysis/supported-logs/syslog)
    1. _Fluentd Syslog (coming soon!)_
3. Application
  1. [NGINX Access](log-analysis/supported-logs/nginx)
  2. _Okta (coming soon!)_
  3. _OneLogin (coming soon!)_
