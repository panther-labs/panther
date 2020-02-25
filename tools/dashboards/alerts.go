package dashboards

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
var alertsJSON = `
{
    "start": "-P1D",
    "widgets": [
        {
            "type": "log",
            "x": 12,
            "y": 15,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-forwarder' | filter component like 'alert_forwarder' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-1",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 15,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-forwarder' | filter component like 'alert_forwarder' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-1",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 18,
            "height": 2,
            "properties": {
                "markdown": "\n## Alert Processing\nPlease refer to Panther [documentation](https://docs.runpanther.io/) for detailed system architecture information.\n\nAll graphs have data aggregated into 5 minute bins. Please refer to our operational [Run Books](https://docs.runpanther.io/operations) for tips on troubleshooting issues.\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 11,
            "width": 18,
            "height": 1,
            "properties": {
                "markdown": "\n### Lambdas\n"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 12,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-alert-processor", "Resource", "panther-alert-processor", { "stat": "Sum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 15,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-alert-forwarder", "Resource", "panther-alert-forwarder", { "stat": "Sum", "region": "us-east-1" } ]
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
            "y": 12,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-alert-processor", "Resource", "panther-alert-processor", { "stat": "Minimum", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-alert-processor", "Resource", "panther-alert-processor", { "stat": "Average", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-alert-processor", "Resource", "panther-alert-processor", { "stat": "Maximum", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 15,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-alert-forwarder", "Resource", "panther-alert-forwarder", { "stat": "Minimum", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-alert-forwarder", "Resource", "panther-alert-forwarder", { "stat": "Average", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-alert-forwarder", "Resource", "panther-alert-forwarder", { "stat": "Maximum", "region": "us-east-1" } ]
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
            "y": 12,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-alert-processor", "Resource", "panther-alert-processor", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-alert-processor", "Resource", "panther-alert-processor", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-1" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": "Errors  / Success (%)",
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
            "x": 9,
            "y": 15,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-alert-forwarder", "Resource", "panther-alert-forwarder", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-alert-forwarder", "Resource", "panther-alert-forwarder", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-1" } ],
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
            "x": 0,
            "y": 2,
            "width": 9,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-forwarder' | SOURCE '/aws/lambda/panther-alert-processor' | filter level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc",
                "region": "us-east-1",
                "stacked": false,
                "title": "Most Recent 20 Errors and Warnings",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 2,
            "width": 9,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-forwarder' | SOURCE '/aws/lambda/panther-alert-processor' | filter  level='error'  or level='warn'\n| stats sum(strcontains(level, 'error')) as errors, sum(strcontains(level, 'warn')) as warns by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Errors and Warnings",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 12,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-processor' | filter component like 'alert_processor' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-1",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 12,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-processor' | filter component like 'alert_processor' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-1",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 8,
            "width": 18,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "panther-alert-processor-dlq", { "yAxis": "right" } ],
                    [ ".", "NumberOfMessagesReceived", ".", "panther-alert-processor-queue" ],
                    [ ".", "NumberOfMessagesSent", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "us-east-1",
                "stat": "Sum",
                "period": 300,
                "title": "Alert Processor  Input SQS Queue Performance"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 15,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Alert Forwarder\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 12,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Alert Processor\n"
            }
        }
    ]
}
`
