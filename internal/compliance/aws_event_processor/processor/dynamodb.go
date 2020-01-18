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

func classifyDynamoDB(detail gjson.Result, accountID string) []*resourceChange {
	eventName := detail.Get("eventName").Str

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazondynamodb.html
	if eventName == "BatchGetItem" ||
		eventName == "ConditionCheckItem" ||
		eventName == "DeleteBackup" ||
		eventName == "DeleteItem" ||
		eventName == "PutItem" ||
		eventName == "Query" ||
		eventName == "Scan" ||
		eventName == "UpdateItem" ||
		eventName == "BatchWriteItem" {

		zap.L().Debug("dynamodb: ignoring event", zap.String("eventName", eventName))
		return nil
	}

	dynamoARN := arn.ARN{
		Partition: "aws",
		Service:   "dynamodb",
		Region:    detail.Get("awsRegion").Str,
		AccountID: accountID,
		Resource:  "table/",
	}
	switch eventName {
	case "CreateBackup", "CreateTable", "DeleteTable", "UpdateContinuousBackups", "UpdateTable", "UpdateTimeToLive":
		dynamoARN.Resource += detail.Get("requestParameters.tableName").Str
	case "CreateGlobalTable":
		var tables []*resourceChange
		dynamoARN.Resource += detail.Get("requestParameters.globalTableName").Str
		for _, repl := range detail.Get("requestParameters.replicationGroup").Array() {
			dynamoARN.Region = repl.Get("regionName").Str
			tables = append(tables, &resourceChange{
				AwsAccountID: accountID,
				EventName:    eventName,
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
					AwsAccountID: accountID,
					EventName:    eventName,
					ResourceID:   dynamoARN.String(),
					ResourceType: schemas.DynamoDBTableSchema,
				})
			}
			region = update.Get("delete.regionName").Str
			if region != "" {
				dynamoARN.Region = region
				tables = append(tables, &resourceChange{
					AwsAccountID: accountID,
					EventName:    eventName,
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
				AwsAccountID: accountID,
				EventName:    eventName,
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
		zap.L().Warn("dynamodb: encountered unknown event name", zap.String("eventName", eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: accountID,
		Delete:       eventName == "DeleteTable",
		EventName:    eventName,
		ResourceID:   dynamoARN.String(),
		ResourceType: schemas.DynamoDBTableSchema,
	}}
}
