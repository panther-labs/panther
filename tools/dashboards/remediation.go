package dashboards

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// nolint:lll
var remediationJSON = `
{
    "start": "-PT1H",
    "widgets": [
        {
            "type": "log",
            "x": 0,
            "y": 3,
            "width": 9,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-processor' | SOURCE '/aws/lambda/panther-remediation-api' | SOURCE '/aws/lambda/panther-aws-remediation' | filter @message like '[ERROR]' or  @message like '[WARN]' or level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc | limit 20",
                "region": "us-east-1",
                "stacked": false,
                "title": "Most Recent 20 Errors and Warnings",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 3,
            "width": 9,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-api' | SOURCE '/aws/lambda/panther-remediation-processor' | SOURCE '/aws/lambda/panther-aws-remediation' | filter  @message like '[ERROR]' or  @message like '[WARN]' or level='error'  or level='warn'\n| stats sum(strcontains(level, 'error')+strcontains(@message, '[ERROR]')) as errors, sum(strcontains(level, 'warn')+strcontains(@message, '[WARN]')) as warns by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Errors and Warnings",
                "view": "timeSeries"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 18,
            "height": 3,
            "properties": {
                "markdown": "\n## Remediation\nPlease refer to Panther [documentation](https://docs.runpanther.io/) for detailed system architecture information.\n\nAll graphs have data aggregated into 5 minute bins. Please refer to our operational [Run Books](https://docs.runpanther.io/operations) for tips on troubleshooting issues.\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 12,
            "width": 18,
            "height": 1,
            "properties": {
                "markdown": "\n### Lambdas\n"
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 9,
            "width": 18,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/SQS", "NumberOfMessagesSent", "QueueName", "panther-remediation-queue" ],
                    [ ".", "NumberOfMessagesReceived", ".", "." ],
                    [ ".", "ApproximateNumberOfMessagesVisible", ".", "panther-remediation-dlq", { "yAxis": "right" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "us-east-1",
                "stat": "Sum",
                "period": 300,
                "title": "Remediation Processor Input SQS Queue Performance"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 19,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-aws-remediation", "Resource", "panther-aws-remediation", { "stat": "Sum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 19,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-aws-remediation", "Resource", "panther-aws-remediation", { "stat": "Minimum", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-aws-remediation", "Resource", "panther-aws-remediation", { "stat": "Average", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-aws-remediation", "Resource", "panther-aws-remediation", { "stat": "Maximum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 16,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-remediation-api", "Resource", "panther-remediation-api", { "stat": "Sum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 16,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-remediation-api", "Resource", "panther-remediation-api", { "stat": "Minimum", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-remediation-api", "Resource", "panther-remediation-api", { "stat": "Average", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-remediation-api", "Resource", "panther-remediation-api", { "stat": "Maximum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 16,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-remediation-api", "Resource", "panther-remediation-api", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-remediation-api", "Resource", "panther-remediation-api", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-1" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Errors / Success (%)",
                "yAxis": {
                    "right": {
                        "max": 100
                    }
                },
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 13,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-remediation-processor", "Resource", "panther-remediation-processor", { "stat": "Sum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 13,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-remediation-processor", "Resource", "panther-remediation-processor", { "stat": "Minimum", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-remediation-processor", "Resource", "panther-remediation-processor", { "stat": "Average", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-remediation-processor", "Resource", "panther-remediation-processor", { "stat": "Maximum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 13,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-remediation-processor", "Resource", "panther-remediation-processor", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-remediation-processor", "Resource", "panther-remediation-processor", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-1" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Errors / Success (%)",
                "yAxis": {
                    "right": {
                        "max": 100
                    }
                },
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 16,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-api' | filter component like 'remediation-api' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-1",
                "title": "Memory Used (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 13,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-processor' | filter component like 'remediation_processor' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-1",
                "title": "Memory Used (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 19,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-aws-remediation", "Resource", "panther-aws-remediation", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-aws-remediation", "Resource", "panther-aws-remediation", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-1" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Errors / Success (%)",
                "yAxis": {
                    "right": {
                        "max": 100
                    }
                },
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 19,
            "width": 6,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-aws-remediation' | filter @message like 'REPORT' | stats max(@maxMemoryUsed/@memorySize) * 100.0 as usage by bin(5min)",
                "region": "us-east-1",
                "title": "Remediation Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 16,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-api' | filter component like 'remediation-api' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-1",
                "title": "Heap Usage (MB)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 13,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-processor' | filter component like 'remediation_processor' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-1",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 19,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Remediation\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 13,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Remediation Processor\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 16,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Remediation API\n"
            }
        }
    ]
}
`
