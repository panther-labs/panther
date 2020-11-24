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

func classifyDynamoDB(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazondynamodb.html
	dynamoARN := arn.ARN{
		Partition: "aws",
		Service:   "dynamodb",
		Region:    metadata.region,
		AccountID: metadata.accountID,
		Resource:  "table/",
	}

	// If a table is being created, most API calls to describe it will fail with a
	// ValidationException. This failure will be retried, but waiting 30 seconds can avoid the
	// failed API call and usually result in a quicker successful scan.
	var delay int64

	switch metadata.eventName {
	case "CreateTable":
		dynamoARN.Resource += detail.Get("requestParameters.tableName").Str
		delay = int64(30)
	case "CreateBackup", "DeleteTable", "UpdateContinuousBackups", "UpdateTable", "UpdateTimeToLive":
		dynamoARN.Resource += detail.Get("requestParameters.tableName").Str
	case "CreateGlobalTable":
		var tables []*resourceChange
		dynamoARN.Resource += detail.Get("requestParameters.globalTableName").Str
		for _, repl := range detail.Get("requestParameters.replicationGroup").Array() {
			dynamoARN.Region = repl.Get("regionName").Str
			tables = append(tables, &resourceChange{
				AwsAccountID: metadata.accountID,
				Delay:        int64(30),
				EventName:    metadata.eventName,
				ResourceID:   dynamoARN.String(),
				ResourceType: schemas.DynamoDBTableSchema,
			})
		}
		return tables
	case "UpdateGlobalTable":
		// What an odd API call...
		var tables []*resourceChange
		dynamoARN.Resource += detail.Get("requestParameters.globalTableName").Str
		for _, update := range detail.Get("requestParameters.replicaUpdates").Array() {
			region := update.Get("create.regionName").Str
			if region != "" {
				dynamoARN.Region = region
				tables = append(tables, &resourceChange{
					AwsAccountID: metadata.accountID,
					EventName:    metadata.eventName,
					ResourceID:   dynamoARN.String(),
					ResourceType: schemas.DynamoDBTableSchema,
				})
			}
			region = update.Get("delete.regionName").Str
			if region != "" {
				dynamoARN.Region = region
				tables = append(tables, &resourceChange{
					AwsAccountID: metadata.accountID,
					EventName:    metadata.eventName,
					ResourceID:   dynamoARN.String(),
					ResourceType: schemas.DynamoDBTableSchema,
				})
			}
		}
		return tables
	case "UpdateGlobalTableSettings":
		// Untested, feels right though
		var tables []*resourceChange
		dynamoARN.Resource += detail.Get("requestParameters.globalTableName").Str
		for _, replica := range detail.Get("responseElements.replicaSettings").Array() {
			dynamoARN.Region = replica.Get("regionName").Str
			tables = append(tables, &resourceChange{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   dynamoARN.String(),
				ResourceType: schemas.DynamoDBTableSchema,
			})
		}
		return tables
	case "RestoreTableFromBackup", "RestoreTableToPointInTime":
		dynamoARN.Resource += detail.Get("requestParameters.targetTableName").Str
	case "TagResource", "UntagResource":
		tableARN, err := arn.Parse(detail.Get("requestParameters.resourceArn").Str)
		if err != nil {
			zap.L().Error("dynamodb: error parsing ARN", zap.Error(err))
			return nil
		}
		dynamoARN = tableARN
	default:
		zap.L().Info("dynamodb: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}
	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delay:        delay,
		Delete:       metadata.eventName == "DeleteTable",
		EventName:    metadata.eventName,
		ResourceID:   dynamoARN.String(),
		ResourceType: schemas.DynamoDBTableSchema,
	}}
}
