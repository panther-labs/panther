package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

const (
	DynamoDBTableSchema = "AWS.DynamoDB.Table"
)

// DynamoDBTable contains all the information about a Dynamo DB table
type DynamoDBTable struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from dynamodb.TableDescription
	AttributeDefinitions   []*dynamodb.AttributeDefinition
	BillingModeSummary     *dynamodb.BillingModeSummary
	GlobalSecondaryIndexes []*dynamodb.GlobalSecondaryIndexDescription
	ItemCount              *int64
	KeySchema              []*dynamodb.KeySchemaElement
	LatestStreamArn        *string
	LatestStreamLabel      *string
	LocalSecondaryIndexes  []*dynamodb.LocalSecondaryIndexDescription
	ProvisionedThroughput  *dynamodb.ProvisionedThroughputDescription
	RestoreSummary         *dynamodb.RestoreSummary
	SSEDescription         *dynamodb.SSEDescription
	StreamSpecification    *dynamodb.StreamSpecification
	TableSizeBytes         *int64
	TableStatus            *string

	// Additional fields
	//
	// Both a Dynamo Table and its Global Secondary Indices can be an auto scaling target
	// This is a list of a table and its indices autoscaling configurations (if they exist)
	//
	AutoScalingDescriptions []*applicationautoscaling.ScalableTarget
	TimeToLiveDescription   *dynamodb.TimeToLiveDescription
}
