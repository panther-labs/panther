---
description: Each supported log type
---

# Supported Logs

Panther can analyze the following log sources to detect threats.

To request a new one, please open a [Github issue](https://github.com/panther-labs/panther/issues)!

## [AWS](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers/awslogs)

AWS contains a variety of critical data sources used to audit API usage, database calls, network traffic, and more.

| Log Type               | Reference                                                                                          |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| `AWS.ALB`              | https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html |
| `AWS.AuroraMySQLAudit` | https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html             |
| `AWS.CloudTrail`       | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html         |
| `AWS.GuardDuty`        | https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html                      |
| `AWS.S3ServerAccess`   | https://docs.aws.amazon.com/AmazonS3/latest/dev/LogFormat.html                                     |
| `AWS.VPCFlow`          | https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html                   |

## [Osquery](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers/osquerylogs)

[Osquery](https://github.com/osquery/osquery) is a tool for SQL powered operating system instrumentation, monitoring, and analytics. It's helpful for collecting data such as installed users, applications, processes, files, system logs, and much more.

| Log Type               | Reference                                                                    |
| ---------------------- | ---------------------------------------------------------------------------- |
| `Osquery.Batch`        | https://osquery.readthedocs.io/en/stable/deployment/logging/#batch-format    |
| `Osquery.Differential` | https://osquery.readthedocs.io/en/stable/deployment/logging/#event-format    |
| `Osquery.Snapshot`     | https://osquery.readthedocs.io/en/stable/deployment/logging/#snapshot-format |
| `Osquery.Status`       | https://osquery.readthedocs.io/en/stable/deployment/logging/#status-logs     |

## [Nginx](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers/nginxlogs)

[Nginx](https://www.nginx.com/) is a powerful open source web server. Nginx logs are configurable, Panther supports the NCSA combined log file format for Access logs.

| Log Type       | Reference                                              |
| -------------- | ------------------------------------------------------ |
| `Nginx.Access` | http://nginx.org/en/docs/http/ngx_http_log_module.html |

## [OSSEC](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers/osseclogs)

[OSSEC](https://www.ossec.net/) is a widely used open source host intrusion detection system. Panther supports the JSON alerts.json log file format for OSSEC EventInfo alerts.

| Log Type          | Reference                                           |
| ----------------- | --------------------------------------------------- |
| `OSSEC.EventInfo` | https://www.ossec.net/docs/docs/formats/alerts.html |

## [Syslog](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers/sysloglogs)

[Syslog](https://en.wikipedia.org/wiki/Syslog) is a protocol for message logging. It has become the standard logging solution on Unix-like systems.

| Log Type          | Reference                                              |
| ----------------- | ------------------------------------------------------ |
| `Syslog.RFC3164`  | https://tools.ietf.org/html/rfc3164                    |


## Built-in Rule Packs

{% hint style="info" %}
Coming soon
{% endhint %}
