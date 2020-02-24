package processor

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

import (
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyCloudWatchLogGroup(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazoncloudwatchlogs.html
	if metadata.eventName == "CancelExportTask" ||
		metadata.eventName == "CreateExportTask" ||
		metadata.eventName == "PutDestination" ||
		metadata.eventName == "PutDestinationPolicy" ||
		metadata.eventName == "PutLogEvents" ||
		metadata.eventName == "PutResourcePolicy" ||
		metadata.eventName == "StartQuery" ||
		metadata.eventName == "StopQuery" ||
		metadata.eventName == "TestMetricFilter" ||
		metadata.eventName == "CreateLogStream" ||
		metadata.eventName == "FilterLogEvents" {

		zap.L().Debug("loggroup: ignoring event", zap.String("eventName", metadata.eventName))
		return nil
	}

	region := detail.Get("awsRegion").Str
	logGroupARN := arn.ARN{
		Partition: "aws",
		Service:   "logs",
		Region:    region,
		AccountID: metadata.accountID,
		Resource:  "log-group:",
	}
	switch metadata.eventName {
	case "AssociateKmsKey", "CreateLogGroup", "DeleteLogGroup", "DeleteLogStream", "DeleteMetricFilter",
		"DeleteRetentionPolicy", "DeleteSubscriptionFilter", "DisassociateKmsKey", "PutMetricFilter",
		"PutRetentionPolicy", "PutSubscriptionFilter", "TagLogGroup", "UntagLogGroup":
		// Not technically the correct resourceID, see classifyCloudFormation for a more detailed
		// explanation.
		logGroupARN.Resource += detail.Get("requestParameters.logGroupName").Str
	default:
		zap.L().Warn("loggroup: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteLogGroup",
		EventName:    metadata.eventName,
		ResourceID:   logGroupARN.String(),
		ResourceType: schemas.CloudWatchLogGroupSchema,
	}}
}
