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
var infraJSON = `
{
    "start": "-PT1H",
    "widgets": [
        {
            "type": "metric",
            "x": 0,
            "y": 9,
            "width": 18,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/SQS", "NumberOfMessagesReceived", "QueueName", "panther-snapshot-queue" ],
                    [ ".", "NumberOfMessagesSent", ".", "." ],
                    [ ".", "ApproximateNumberOfMessagesVisible", ".", "panther-snapshot-queue-dlq", { "yAxis": "right" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "us-east-2",
                "stat": "Sum",
                "period": 300,
                "title": "Snapshot Poller Input SQS Queue Performance"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 18,
            "height": 3,
            "properties": {
                "markdown": "\n# Infrastructure Monitoring\nPlease refer to Panther [documentation](https://docs.runpanther.io/) for detailed system architecture information.\n\nAll graphs have data aggregated into 5 minute bins. Please refer to our operational [Run Books](https://docs.runpanther.io/operations) for tips on troubleshooting issues.\n"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 31,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-source-api", "Resource", "panther-source-api", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 31,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-source-api", "Resource", "panther-source-api", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-source-api", "Resource", "panther-source-api", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-source-api", "Resource", "panther-source-api", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 31,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-source-api", "Resource", "panther-source-api", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-source-api", "Resource", "panther-source-api", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
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
            "y": 34,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-snapshot-scheduler", "Resource", "panther-snapshot-scheduler", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 34,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-snapshot-scheduler", "Resource", "panther-snapshot-scheduler", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-snapshot-scheduler", "Resource", "panther-snapshot-scheduler", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-snapshot-scheduler", "Resource", "panther-snapshot-scheduler", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 34,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-snapshot-scheduler", "Resource", "panther-snapshot-scheduler", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-snapshot-scheduler", "Resource", "panther-snapshot-scheduler", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
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
            "y": 37,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-snapshot-pollers", "Resource", "panther-snapshot-pollers", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 37,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-snapshot-pollers", "Resource", "panther-snapshot-pollers", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-snapshot-pollers", "Resource", "panther-snapshot-pollers", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-snapshot-pollers", "Resource", "panther-snapshot-pollers", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 37,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-snapshot-pollers", "Resource", "panther-snapshot-pollers", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-snapshot-pollers", "Resource", "panther-snapshot-pollers", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
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
            "y": 40,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-aws-event-processor", "Resource", "panther-aws-event-processor", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 40,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-aws-event-processor", "Resource", "panther-aws-event-processor", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-aws-event-processor", "Resource", "panther-aws-event-processor", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-aws-event-processor", "Resource", "panther-aws-event-processor", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 40,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-aws-event-processor", "Resource", "panther-aws-event-processor", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-aws-event-processor", "Resource", "panther-aws-event-processor", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
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
            "y": 31,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-source-api' | filter component like 'snapshot' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 31,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-source-api' | filter component like 'snapshot' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "title": "Heap Usage (MB)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 34,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-snapshot-scheduler' | filter component like 'snapshot' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 34,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-snapshot-scheduler' | filter component like 'snapshot' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 37,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-snapshot-pollers' | filter component like 'snapshot' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 37,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-snapshot-pollers' | filter component like 'snapshot' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "title": "Heap Usage (MB)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 24,
            "width": 18,
            "height": 1,
            "properties": {
                "markdown": "\n### Lambdas\n"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 49,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-policy-engine", "Resource", "panther-policy-engine", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 49,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-policy-engine", "Resource", "panther-policy-engine", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-policy-engine", "Resource", "panther-policy-engine", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-policy-engine", "Resource", "panther-policy-engine", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 49,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-policy-engine", "Resource", "panther-policy-engine", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-policy-engine", "Resource", "panther-policy-engine", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
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
            "y": 49,
            "width": 6,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-policy-engine' | filter @message like 'REPORT' | stats max(@maxMemoryUsed/@memorySize) * 100.0 as usage by bin(5min)",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 18,
            "width": 18,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-aws-event-processor' | filter  @message like 'unknown event name'\n| fields @timestamp, eventName, msg, @message\n| sort @timestamp desc | limit 20  ",
                "region": "us-east-2",
                "stacked": false,
                "title": "Unknown Events",
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
                "query": "SOURCE '/aws/lambda/panther-aws-event-processor' | SOURCE '/aws/lambda/panther-source-api' | SOURCE '/aws/lambda/panther-snapshot-pollers' | SOURCE '/aws/lambda/panther-snapshot-scheduler' | SOURCE '/aws/lambda/panther-resources-api' | SOURCE '/aws/lambda/panther-resource-processor' | SOURCE '/aws/lambda/panther-policy-engine' | SOURCE '/aws/lambda/panther-compliance-api' | SOURCE '/aws/lambda/panther-analysis-api' | filter  @message like '[ERROR]' or  @message like '[WARN]' or level='error'  or level='warn'\n| stats sum(strcontains(level, 'error')+strcontains(@message, '[ERROR]')) as errors, sum(strcontains(level, 'warn')+strcontains(@message, '[WARN]')) as warns by bin(5m)",
                "region": "us-east-2",
                "stacked": false,
                "title": "Errors and Warnings",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 46,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-resource-processor", "Resource", "panther-resource-processor", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Resource Processor Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 46,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-resource-processor", "Resource", "panther-resource-processor", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-resource-processor", "Resource", "panther-resource-processor", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-resource-processor", "Resource", "panther-resource-processor", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 46,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-resource-processor", "Resource", "panther-resource-processor", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-resource-processor", "Resource", "panther-resource-processor", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
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
            "y": 40,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-aws-event-processor' | filter component like 'aws_event_processor' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 40,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-aws-event-processor' | filter component like 'aws_event_processor' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 43,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-resources-api", "Resource", "panther-resources-api", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 43,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-resources-api", "Resource", "panther-resources-api", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-resources-api", "Resource", "panther-resources-api", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-resources-api", "Resource", "panther-resources-api", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 43,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-resources-api", "Resource", "panther-resources-api", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-resources-api", "Resource", "panther-resources-api", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
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
            "y": 43,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-resources-api' | filter component like 'panther-resources-api' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 43,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-resources-api' | filter component like 'panther-resources-api' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 12,
            "width": 18,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/SQS", "NumberOfMessagesSent", "QueueName", "panther-aws-events-queue" ],
                    [ ".", "NumberOfMessagesReceived", ".", "." ],
                    [ ".", "ApproximateNumberOfMessagesVisible", ".", "panther-aws-events-queue-dlq", { "yAxis": "right" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "us-east-2",
                "stat": "Sum",
                "period": 300,
                "title": "AWS Event Processor Input SQS Queue Performance"
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 15,
            "width": 18,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/SQS", "NumberOfMessagesReceived", "QueueName", "panther-resources-queue" ],
                    [ ".", "ApproximateNumberOfMessagesVisible", ".", "panther-resources-queue-dlq", { "yAxis": "right" } ],
                    [ ".", "NumberOfMessagesSent", ".", "panther-resources-queue" ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "us-east-2",
                "stat": "Sum",
                "period": 300,
                "title": "Rource Processor Input SQS Queue Performance"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 46,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-resource-processor' | filter component like 'resource_processor' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 46,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-resource-processor' | filter component like 'resource_processor' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 49,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Policy Engine\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 31,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Snapshot API\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 34,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Snapshot Scheduler\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 37,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Snapshot Poller\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 40,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Event Processor\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 43,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Resources API\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 46,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Resource Processor\n"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 28,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-compliance-api", "Resource", "panther-compliance-api", { "stat": "Sum" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations"
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 28,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-compliance-api", "Resource", "panther-compliance-api", { "stat": "Minimum" } ],
                    [ "...", { "stat": "Average" } ],
                    [ "...", { "stat": "Maximum" } ]
                ],
                "region": "us-east-2"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 28,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-compliance-api", "Resource", "panther-compliance-api", { "id": "errors", "stat": "Sum", "color": "#d13212" } ],
                    [ ".", "Invocations", ".", ".", ".", ".", { "id": "invocations", "stat": "Sum", "visible": false } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right" } ]
                ],
                "region": "us-east-2",
                "title": "Errors / Success (%)",
                "yAxis": {
                    "right": {
                        "max": 100
                    }
                }
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 28,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Compliance API\n"
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 28,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-compliance-api' | filter component like 'compliance' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 28,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-compliance-api' | filter component like 'compliance' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 25,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Analysis API\n"
            }
        },
        {
            "type": "log",
            "x": 15,
            "y": 25,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-analysis-api' | filter component like 'analysis' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-2",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 25,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-analysis-api' | filter component like 'analysis' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-2",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 25,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-analysis-api", "Resource", "panther-analysis-api", { "stat": "Sum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 25,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-analysis-api", "Resource", "panther-analysis-api", { "stat": "Minimum", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-analysis-api", "Resource", "panther-analysis-api", { "stat": "Average", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-analysis-api", "Resource", "panther-analysis-api", { "stat": "Maximum", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 25,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-analysis-api", "Resource", "panther-analysis-api", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-2" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-analysis-api", "Resource", "panther-analysis-api", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-2" } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-2" } ]
                ],
                "region": "us-east-2",
                "title": "Errors and Success (%)",
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
            "y": 3,
            "width": 9,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-source-api' | SOURCE '/aws/lambda/panther-snapshot-pollers' | SOURCE '/aws/lambda/panther-snapshot-scheduler' | SOURCE '/aws/lambda/panther-aws-event-processor' | SOURCE '/aws/lambda/panther-resources-api' | SOURCE '/aws/lambda/panther-resource-processor' | SOURCE '/aws/lambda/panther-policy-engine' | SOURCE '/aws/lambda/panther-compliance-api' | SOURCE '/aws/lambda/panther-analysis-api' | filter  @message like '[ERROR]' or  @message like '[WARN]' or level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc | limit 20  ",
                "region": "us-east-2",
                "stacked": false,
                "title": "Most Recent 20 Errors and Warnings",
                "view": "table"
            }
        }
    ]
}
`
