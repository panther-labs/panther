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
var overviewJSON = `
{
    "start": "-PT1H",
    "widgets": [
        {
            "type": "log",
            "x": 0,
            "y": 3,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | SOURCE '/aws/lambda/panther-rules-engine' | filter @message like '[ERROR]' or  @message like '[WARN]' or level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc\n| limit 20",
                "region": "us-west-2",
                "title": "Log Processing and Rules Engine Most Recent 20 Errors and Warnings",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 3,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | SOURCE '/aws/lambda/panther-log-processor' | filter @message like '[ERROR]' or level='error' or @message like '[WARN]' or level='warn'\n| fields strcontains(@message, '[ERROR']) as ruleError, strcontains(@message, '[WARN']) as ruleWarn, level \n| stats sum(ruleError) as rule_errors, sum(ruleWarn) as rule_warns, sum(strcontains(level, 'error')) as log_errors, sum(strcontains(level, 'warn')) as log_warns by bin(5m)",
                "region": "us-west-2",
                "stacked": false,
                "title": "Log Processing and Rules Engine  Errors and Warnings",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 6,
            "width": 6,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter ispresent(stats.LogType)  | stats count(stats.LogType) as files by stats.LogType as logtype | sort files desc",
                "region": "us-west-2",
                "title": "Input File Count by Log Type",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 6,
            "y": 6,
            "width": 6,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter ispresent(stats.LogType)  | stats sum(stats.BytesProcessedCount) / 1000000 as mbbytes by stats.LogType as logtype | sort mbbytes desc",
                "region": "us-west-2",
                "title": "Input MBytes (Uncompressed) by Log Type",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 9,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-log-processor' | filter operation='sendData' | stats sum(contentLength) / 1000000 as mbbytes by bin(5m)",
                "region": "us-west-2",
                "stacked": false,
                "title": "Log Processing Ouptut  MBytes (Compressed) Written to S3",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 6,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | filter @message like 'Retrieved' | parse @message \"Retrieved * rules in * seconds\" as nrules, ruleloadtime | stats max(nrules) as rules by bin(5m)\n",
                "region": "us-west-2",
                "stacked": false,
                "title": "Number of Loaded Rules",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 9,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-rules-engine' | filter @message like 'Matched' | parse @message \"Matched * events in * seconds\" as nevents, rulematchtime | stats sum(nevents) as matches by bin(5m)\n",
                "region": "us-west-2",
                "stacked": false,
                "title": "Number of Rule Matches",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 12,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-source-api' | SOURCE '/aws/lambda/panther-snapshot-pollers' | SOURCE '/aws/lambda/panther-snapshot-scheduler' | SOURCE '/aws/lambda/panther-aws-event-processor' | SOURCE '/aws/lambda/panther-resources-api' | SOURCE '/aws/lambda/panther-resource-processor' | SOURCE '/aws/lambda/panther-policy-engine' | SOURCE '/aws/lambda/panther-analysis-api' | SOURCE '/aws/lambda/panther-compliance-api' | filter  @message like '[ERROR]' or  @message like '[WARN]' or level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc | limit 20",
                "region": "us-west-2",
                "stacked": false,
                "title": "Infrastructure Monitoring Recent 20 Errors and Warnings",
                "view": "table"
            }
        },
        {
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 24,
            "height": 3,
            "properties": {
                "markdown": "\n# Panther System Overview\n\nPlease refer to Panther [documentation](https://docs.runpanther.io/) for detailed system architecture information.\n\nAll graphs have data aggregated into 5 minute bins. Please refer to our operational [Run Books](https://docs.runpanther.io/operations) for tips on troubleshooting issues.\n"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 12,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-aws-event-processor' | SOURCE '/aws/lambda/panther-source-api' | SOURCE '/aws/lambda/panther-snapshot-pollers' | SOURCE '/aws/lambda/panther-snapshot-scheduler' | SOURCE '/aws/lambda/panther-resources-api' | SOURCE '/aws/lambda/panther-resource-processor' | SOURCE '/aws/lambda/panther-policy-engine' | SOURCE '/aws/lambda/panther-analysis-api' | SOURCE '/aws/lambda/panther-compliance-api' | filter  @message like '[ERROR]' or  @message like '[WARN]' or level='error'  or level='warn'\n| stats sum(strcontains(level, 'error')+strcontains(@message, '[ERROR]')) as errors, sum(strcontains(level, 'warn')+strcontains(@message, '[WARN]')) as warns by bin(5m)",
                "region": "us-west-2",
                "stacked": false,
                "title": "Infrastructure Monitoring Errors and Warnings",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 15,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-forwarder' | SOURCE '/aws/lambda/panther-alert-processor' | SOURCE '/aws/lambda/panther-alert-delivery-api' | filter level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc | limit 20",
                "region": "us-west-2",
                "stacked": false,
                "title": "Alert Processing Recent 20 Errors and Warnings",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 15,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-alert-forwarder' | SOURCE '/aws/lambda/panther-alert-processor' | SOURCE '/aws/lambda/panther-alert-delivery-api' | filter  level='error'  or level='warn'\n| stats sum(strcontains(level, 'error')) as errors, sum(strcontains(level, 'warn')) as warns by bin(5m)",
                "region": "us-west-2",
                "stacked": false,
                "title": "Alert Processing Errors and Warnings",
                "view": "timeSeries"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 18,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-processor' | SOURCE '/aws/lambda/panther-remediation-api' | SOURCE '/aws/lambda/panther-aws-remediation' | filter @message like '[ERROR]' or  @message like '[WARN]' or level='error' or level='warn'\n| fields @timestamp, @message\n| sort @timestamp desc | limit 20",
                "region": "us-west-2",
                "title": "Remediation Recent 20 Errors and Warnings",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 18,
            "width": 12,
            "height": 3,
            "properties": {
                "query": "SOURCE '/aws/lambda/panther-remediation-api' | SOURCE '/aws/lambda/panther-remediation-processor' | SOURCE '/aws/lambda/panther-aws-remediation' | filter  @message like '[ERROR]' or  @message like '[WARN]' or level='error'  or level='warn'\n| stats sum(strcontains(level, 'error')+strcontains(@message, '[ERROR]')) as errors, sum(strcontains(level, 'warn')+strcontains(@message, '[WARN]')) as warns by bin(5m)",
                "region": "us-west-2",
                "title": "Remediation Errors and Warnings",
                "view": "table"
            }
        }
    ]
}
`
