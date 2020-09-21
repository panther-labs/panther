package processor

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

import (
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyCloudTrail(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awscloudtrail.html
	trailARNBase := arn.ARN{
		Partition: "aws",
		Service:   "cloudtrail",
		Region:    metadata.region,
		AccountID: metadata.accountID,
	}
	var err error

	// WARNING: regional service scans for CloudTrail are ignored, and default to account wide scans.
	// This is to ensure the correctness of the CloudTrail.Meta resource.
	switch metadata.eventName {
	case "AddTags", "RemoveTags":
		// This will always be an ARN
		trailARNBase, err = arn.Parse(detail.Get("requestParameters.resourceId").Str)
		if err != nil {
			zap.L().Error("cloudtrail: unable to parse ARN",
				zap.String("eventName", metadata.eventName),
				zap.String("resourceId", detail.Get("requestParameters.resourceId").Str))
			return nil
		}
	case "StartLogging", "StopLogging", "UpdateTrail":
		// The name requestParameter could be either the trail name or the trail ARN, so we try both
		trailARN, err := arn.Parse(detail.Get("requestParameters.name").Str)
		if err == nil {
			trailARNBase = trailARN
		} else {
			trailARNBase.Resource = "trail/" + detail.Get("requestParameters.name").Str
		}
	case "CreateTrail", "PutEventSelectors":
		// These events may effect the CloudTrail Meta resource, so must launch a full account scan
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceType: schemas.CloudTrailSchema,
		}}
	case "DeleteTrail":
		// The name requestParameter could be either the trail name or the trail ARN, so we try both
		// Special case of full account scan where we must also delete a resource
		trailARN, err := arn.Parse(detail.Get("requestParameters.name").Str)
		if err == nil {
			trailARNBase = trailARN
		} else {
			trailARNBase.Resource = "trail/" + detail.Get("requestParameters.name").Str
		}
		return []*resourceChange{
			{
				AwsAccountID: metadata.accountID,
				Delete:       true,
				EventName:    metadata.eventName,
				ResourceID:   trailARNBase.String(),
				ResourceType: schemas.CloudTrailSchema,
			},
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceType: schemas.CloudTrailSchema,
			}}
	default:
		zap.L().Info("cloudtrail: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	// This will only happen when the name parameter is an ARN and also the resource exists in a
	// different account than the account this event was logged in
	if metadata.accountID != trailARNBase.AccountID {
		zap.L().Info("cloudtrail: discarding resource from another account",
			zap.String("ResourceID", trailARNBase.String()),
			zap.String("AccountID", metadata.accountID))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       false,
		EventName:    metadata.eventName,
		ResourceID:   trailARNBase.String(),
		ResourceType: schemas.CloudTrailSchema,
	}}
}
