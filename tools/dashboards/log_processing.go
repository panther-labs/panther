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
var logProcessingJSON = `
{
    "start": "-P1D",
    "widgets": [
        {
            "type": "log",
            "x": 0,
            "y": 3,
            "width": 9,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | SOURCE '/aws/lambda/panther-rules-engine' | filter @message like '[ERROR]' or  @message like '[WARN]' or level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc\n| limit 20",
                "region": "us-east-1",
                "stacked": false,
                "title": "Most Recent 20 Errors and Warnings",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 23,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter ispresent(stats.LogType) | stats sum(stats.BytesProcessedCount)/(1000000) as mbbytes by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Input MBytes (Uncompressed) Processed",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 29,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | stats sum(stats.EventCount) as events by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Output Events Written to S3",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 26,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter operation='readS3Object' | stats percentile(opTime, 50)*1000.0 as p50, percentile(opTime, 90)*1000.0 as p90, percentile(opTime, 95)*1000.0 as p95, percentile(opTime, 100)*1000.0 as p100 by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Input File Read Time Percentiles (msec)",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 17,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter ispresent(stats.LogType)  | stats count(stats.LogType) as files by stats.LogType as logtype | sort files desc",
                "region": "us-east-1",
                "stacked": false,
                "title": "Input File Count by Log Type",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 23,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter operation='readS3Object' | stats count(*) as files by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Input Files Processed",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 20,
            "width": 18,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "panther-input-data-notifications-dlq", { "yAxis": "right" } ],
                    [ ".", "NumberOfMessagesReceived", ".", "panther-input-data-notifications" ],
                    [ ".", "NumberOfMessagesSent", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "us-east-1",
                "stat": "Sum",
                "period": 300,
                "title": "Input SQS Queue Performance",
                "legend": {
                    "position": "bottom"
                }
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 32,
            "width": 18,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/SNS", "NumberOfMessagesPublished", "TopicName", "panther-processed-data-notifications" ],
                    [ ".", "NumberOfNotificationsFailed", ".", "." ],
                    [ ".", "NumberOfNotificationsDelivered", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "us-east-1",
                "stat": "Sum",
                "period": 300,
                "title": "Output File Notification SNS Performance",
                "legend": {
                    "position": "bottom"
                }
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 26,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter operation='parse' | filter ispresent(stats.LogType)  | stats percentile(opTime, 50)*1000.0 as p50, percentile(opTime, 90)*1000.0 as p90, percentile(opTime, 95)*1000.0 as p95, percentile(opTime, 100)*1000.0 as p100 by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Processng Time Percentiles (msec)",
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
                "markdown": "\n# [Log Processing](https://docs.runpanther.io/log-analysis/log-processing) \nThe log processing Input SQS Queue receives S3 event notifications from buckets users configure for log processing. A Lambda function processes each file into JSON and appends the [Panther Fields](https://docs.runpanther.io/historical-search/panther-fields). The new JSON files are written to S3 and notifications are sent to the Output File Notification SNS topic to trigger the [Rules Engine](https://docs.runpanther.io/log-analysis/rules).\n\nThe Rules Engine reads file names in S3 notifications sent to the Input SQS Queue from the output of the [log processing](https://docs.runpanther.io/log-analysis/log-processing) subsystem. The engine applies the configured rules to each file. Those events that match are written to S3 for historical search and alarms generated per the set deduplication string and alarm interval for each rule.The alarms are sent to the Alert Output SQS Queue for delivery to user configured [destinations](https://docs.runpanther.io/destinations/background).\n\nAll graphs have data aggregated into 5 minute bins. Please refer to our operational [Run Books](https://docs.runpanther.io/operations) for tips on troubleshooting issues.\n"
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 29,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter operation='sendData' | stats sum(contentLength) / 1000000 as mbbytes by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Ouptut  MBytes (Compressed) Written to S3",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 17,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter ispresent(stats.LogType)  | stats sum(stats.BytesProcessedCount) / 1000000 as mbbytes by stats.LogType as logtype | sort mbbytes desc",
                "region": "us-east-1",
                "stacked": false,
                "title": "Input MBytes (Uncompressed) by Log Type",
                "view": "table"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 36,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-log-processor", "Resource", "panther-log-processor", { "stat": "Sum" } ]
                ],
                "region": "us-east-1",
                "title": "Invocations",
                "start": "-PT3H",
                "end": "P0D",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 36,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-log-processor", "Resource", "panther-log-processor", { "stat": "Minimum", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-log-processor", "Resource", "panther-log-processor", { "stat": "Average", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-log-processor", "Resource", "panther-log-processor", { "stat": "Maximum", "region": "us-east-1" } ]
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
            "y": 36,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-log-processor", "Resource", "panther-log-processor", { "id": "errors", "stat": "Sum", "color": "#d13212", "region": "us-east-1" } ],
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-log-processor", "Resource", "panther-log-processor", { "id": "invocations", "stat": "Sum", "visible": false, "region": "us-east-1" } ],
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
            "x": 15,
            "y": 36,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter operation like 'panther-log-processor' | stats max(heapSizeMB) as heap by bin(5min)\n",
                "region": "us-east-1",
                "stacked": false,
                "title": "Heap Usage (MB)",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 3,
            "y": 39,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", "panther-rules-engine", "Resource", "panther-rules-engine", { "stat": "Sum" } ]
                ],
                "region": "us-east-1",
                "title": "Invocations",
                "view": "timeSeries",
                "stacked": false,
                "start": "-P1D",
                "end": "P0D"
            }
        },
        {
            "type": "metric",
            "x": 6,
            "y": 39,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", "panther-rules-engine", "Resource", "panther-rules-engine", { "stat": "Minimum" } ],
                    [ "...", { "stat": "Average" } ],
                    [ "...", { "stat": "Maximum" } ]
                ],
                "region": "us-east-1",
                "view": "timeSeries",
                "stacked": false,
                "title": "Duration (msec)",
                "start": "-P1D",
                "end": "P0D"
            }
        },
        {
            "type": "metric",
            "x": 9,
            "y": 39,
            "width": 3,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", "panther-rules-engine", "Resource", "panther-rules-engine", { "id": "errors", "stat": "Sum", "color": "#d13212" } ],
                    [ ".", "Invocations", ".", ".", ".", ".", { "id": "invocations", "stat": "Sum", "visible": false } ],
                    [ { "expression": "100 - 100 * errors / MAX([errors, invocations])", "label": "Success rate (%)", "id": "availability", "yAxis": "right", "region": "us-east-1" } ]
                ],
                "region": "us-east-1",
                "title": " Errors / Success (%)",
                "yAxis": {
                    "right": {
                        "max": 100
                    }
                },
                "view": "timeSeries",
                "stacked": false,
                "start": "-P1D",
                "end": "P0D"
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 3,
            "width": 9,
            "height": 6,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | SOURCE '/aws/lambda/panther-log-processor' | filter @message like '[ERROR]' or level='error' or @message like '[WARN]' or level='warn'\n| fields strcontains(@message, '[ERROR']) as ruleError, strcontains(@message, '[WARN']) as ruleWarn, level \n| stats sum(ruleError) as rule_errors, sum(ruleWarn) as rule_warns, sum(strcontains(level, 'error')) as log_errors, sum(strcontains(level, 'warn')) as log_warns by bin(5m)",
                "region": "us-east-1",
                "stacked": false,
                "title": "Errors and Warnings",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 10,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | filter @message like 'Retrieved' | parse @message \"Retrieved * rules in * seconds\" as nrules, ruleloadtime | stats max(nrules) as rules by bin(5m)\n",
                "region": "us-east-1",
                "title": "Number of Loaded Rules",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 10,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | filter @message like 'Retrieved' | parse @message \"Retrieved * rules in * seconds\" as nrules, ruleloadtime | stats percentile(ruleloadtime, 50)*1000.0 as p50, percentile(ruleloadtime, 90)*1000.0  as p90, percentile(ruleloadtime, 95)*1000.0  as p95, percentile(ruleloadtime, 100)*1000.0  as p100 by bin(5m)\n",
                "region": "us-east-1",
                "title": "Rule Load Time Percentiles (msec)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 13,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | filter @message like 'Matched' | parse @message \"Matched * events in * seconds\" as nevents, rulematchtime | stats percentile(rulematchtime, 50)*1000.0 as p50, percentile(rulematchtime, 90)*1000.0  as p90, percentile(rulematchtime, 95)*1000.0  as p95, percentile(rulematchtime, 100)*1000.0  as p100 by bin(5m)\n",
                "region": "us-east-1",
                "title": "Match Time per File  Percentiles (msec)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 9,
            "y": 13,
            "width": 9,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | filter @message like 'Matched' | parse @message \"Matched * events in * seconds\" as nevents, rulematchtime | stats sum(nevents) as matches by bin(5m)\n",
                "region": "us-east-1",
                "stacked": false,
                "title": "Number of Rule Matches",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 36,
            "width": 3,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter operation like 'panther-log-processor' | stats max(percentMemUsed) as used by bin(5min)\n",
                "region": "us-east-1",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 39,
            "width": 6,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | filter @message like 'REPORT' | stats max(@maxMemoryUsed/@memorySize) * 100.0 as usage by bin(5min)",
                "region": "us-east-1",
                "title": "Memory Usage (%)",
                "view": "timeSeries",
                "stacked": false
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 39,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Rules Engine\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 16,
            "width": 18,
            "height": 1,
            "properties": {
                "markdown": "\n## Processing\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 36,
            "width": 3,
            "height": 3,
            "properties": {
                "markdown": "\n### Log Processor\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 35,
            "width": 18,
            "height": 1,
            "properties": {
                "markdown": "\n## Lambdas\n"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 9,
            "width": 18,
            "height": 1,
            "properties": {
                "markdown": "\n## Rules\n"
            }
        }
    ]
}
`
