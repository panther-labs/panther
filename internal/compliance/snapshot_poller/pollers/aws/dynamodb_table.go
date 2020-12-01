package aws

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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling/applicationautoscalingiface"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

const (
	dynamoDBServiceNameSpace = "dynamodb"
	// Several DynamoDB API calls (most noticeably the DescribeTimeToLive API call) have very low
	// rate limits, so we set the max batch size lower than for most resource types to avoid getting
	// rate limited.
	dynamodbBatchSize = 20
)

// Set as variables to be overridden in testing
var (
	DynamoDBClientFunc               = setupDynamoDBClient
	ApplicationAutoScalingClientFunc = setupApplicationAutoScalingClient
)

func setupDynamoDBClient(sess *session.Session, cfg *aws.Config) interface{} {
	return dynamodb.New(sess, cfg)
}

func getDynamoDBClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (dynamodbiface.DynamoDBAPI, error) {

	client, err := getClient(pollerResourceInput, DynamoDBClientFunc, "dynamodb", region)
	if err != nil {
		return nil, err
	}

	return client.(dynamodbiface.DynamoDBAPI), nil
}

func setupApplicationAutoScalingClient(sess *session.Session, cfg *aws.Config) interface{} {
	return applicationautoscaling.New(sess, cfg)
}

func getApplicationAutoScalingClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (applicationautoscalingiface.ApplicationAutoScalingAPI, error) {

	client, err := getClient(pollerResourceInput, ApplicationAutoScalingClientFunc, "applicationautoscaling", region)
	if err != nil {
		return nil, err
	}

	return client.(applicationautoscalingiface.ApplicationAutoScalingAPI), nil
}

// PollDynamoDBTable polls a single DynamoDB Table resource
func PollDynamoDBTable(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	_ *pollermodels.ScanEntry,
) (interface{}, error) {

	dynamoClient, err := getDynamoDBClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	autoscalingClient, err := getApplicationAutoScalingClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	table := strings.Replace(resourceARN.Resource, "table/", "", 1)

	snapshot, err := buildDynamoDBTableSnapshot(dynamoClient, autoscalingClient, aws.String(table))
	if err != nil || snapshot == nil {
		return nil, err
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	return snapshot, nil
}

// listTables returns a list of all Dynamo DB tables in the account
func listTables(dynamoDBSvc dynamodbiface.DynamoDBAPI, nextMarker *string) (tables []*string, marker *string, err error) {
	err = dynamoDBSvc.ListTablesPages(&dynamodb.ListTablesInput{
		ExclusiveStartTableName: nextMarker,
		Limit:                   aws.Int64(int64(dynamodbBatchSize)),
	},
		func(page *dynamodb.ListTablesOutput, lastPage bool) bool {
			return dynamoTableIterator(page, &tables, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "DynamoDB.ListTablesPages")
	}
	return
}

func dynamoTableIterator(page *dynamodb.ListTablesOutput, tables *[]*string, marker **string) bool {
	*tables = append(*tables, page.TableNames...)
	// DynamoDB uses the name of the last table evaluated as the pagination marker
	*marker = page.LastEvaluatedTableName
	return len(*tables) < dynamodbBatchSize
}

// describeTable provides detailed information about a given DynamoDB table
func describeTable(dynamoDBSvc dynamodbiface.DynamoDBAPI, name *string) (*dynamodb.TableDescription, error) {
	out, err := dynamoDBSvc.DescribeTable(&dynamodb.DescribeTableInput{TableName: name})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == dynamodb.ErrCodeResourceNotFoundException {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *name),
				zap.String("resourceType", awsmodels.DynamoDBTableSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "DynamoDB.DescribeTable: %s", aws.StringValue(name))
	}

	return out.Table, nil
}

// describeTimeToLive provides time to live configuration information
func describeTimeToLive(dynamoDBSvc dynamodbiface.DynamoDBAPI, name *string) (*dynamodb.TimeToLiveDescription, error) {
	out, err := dynamoDBSvc.DescribeTimeToLive(&dynamodb.DescribeTimeToLiveInput{TableName: name})
	if err != nil {
		return nil, errors.Wrapf(err, "DynamoDB.DescribeTimeToLive: %s", aws.StringValue(name))
	}

	return out.TimeToLiveDescription, nil
}

// listTagsOfResource returns the tags for a given DynamoDB table
func listTagsOfResource(dynamoDBSvc dynamodbiface.DynamoDBAPI, arn *string) ([]*dynamodb.Tag, error) {
	out, err := dynamoDBSvc.ListTagsOfResource(&dynamodb.ListTagsOfResourceInput{ResourceArn: arn})
	if err != nil {
		return nil, errors.Wrapf(err, "DynamoDB.ListTagsOfResource: %s", aws.StringValue(arn))
	}

	return out.Tags, nil
}

// describeScalableTargets provides information about autoscaling for a given resource
// Gathers autoscaling configuration on both a DynamoDB table and its Global Secondary Indices (GSI's)
func describeScalableTargets(
	applicationAutoScalingSvc applicationautoscalingiface.ApplicationAutoScalingAPI,
	resourceIDs []*string,
) (autoscaling []*applicationautoscaling.ScalableTarget, err error) {

	input := &applicationautoscaling.DescribeScalableTargetsInput{
		ResourceIds:      resourceIDs,
		ServiceNamespace: aws.String(dynamoDBServiceNameSpace),
	}
	err = applicationAutoScalingSvc.DescribeScalableTargetsPages(input,
		func(page *applicationautoscaling.DescribeScalableTargetsOutput, lastPage bool) bool {
			autoscaling = append(autoscaling, page.ScalableTargets...)
			return true
		})
	if err != nil {
		// Difficult to print the values of a slice of string pointers, so we append context in
		// the calling function
		return nil, errors.Wrap(err, "ApplicationAutoScaling.DescribeScalableTargetsPages")
	}

	return
}

// buildDynamoDBTableSnapshot builds a snapshot of a DynamoDB table, including information about its
// Global Secondary Indices (GSI's) and any applicable autoscaling information for the table and GSI's
func buildDynamoDBTableSnapshot(
	dynamoDBSvc dynamodbiface.DynamoDBAPI,
	applicationAutoScalingSvc applicationautoscalingiface.ApplicationAutoScalingAPI,
	tableName *string,
) (*awsmodels.DynamoDBTable, error) {

	description, err := describeTable(dynamoDBSvc, tableName)
	// description will be nil if the resource no longer exists
	if err != nil || description == nil {
		return nil, err
	}

	table := &awsmodels.DynamoDBTable{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.DynamoDBTableSchema),
			ResourceID:   description.TableArn,
			TimeCreated:  description.CreationDateTime,
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name: tableName,
			ARN:  description.TableArn,
			ID:   description.TableId,
		},
		AttributeDefinitions:   description.AttributeDefinitions,
		BillingModeSummary:     description.BillingModeSummary,
		GlobalSecondaryIndexes: description.GlobalSecondaryIndexes,
		ItemCount:              description.ItemCount,
		KeySchema:              description.KeySchema,
		LatestStreamArn:        description.LatestStreamArn,
		LatestStreamLabel:      description.LatestStreamLabel,
		LocalSecondaryIndexes:  description.LocalSecondaryIndexes,
		ProvisionedThroughput:  description.ProvisionedThroughput,
		RestoreSummary:         description.RestoreSummary,
		SSEDescription:         description.SSEDescription,
		StreamSpecification:    description.StreamSpecification,
		TableSizeBytes:         description.TableSizeBytes,
		TableStatus:            description.TableStatus,
	}

	tableID := aws.String("table/" + *tableName)
	resourceIDs := []*string{tableID}

	ttl, err := describeTimeToLive(dynamoDBSvc, tableName)
	if err != nil {
		return nil, err
	}
	table.TimeToLiveDescription = ttl

	for _, index := range description.GlobalSecondaryIndexes {
		indexID := aws.String(*tableID + "/index/" + *index.IndexName)
		resourceIDs = append(resourceIDs, indexID)
	}

	tags, err := listTagsOfResource(dynamoDBSvc, table.ARN)
	if err != nil {
		return nil, err
	}
	table.Tags = utils.ParseTagSlice(tags)

	if table.AutoScalingDescriptions, err = describeScalableTargets(applicationAutoScalingSvc, resourceIDs); err != nil {
		return nil, errors.WithMessagef(err, "table: %s", aws.StringValue(tableName))
	}

	return table, nil
}

// PollDynamoDBTables gathers information on each Dynamo DB Table for an AWS account.
func PollDynamoDBTables(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting DynamoDB Table resource poller")
	dynamoDBSvc, err := getDynamoDBClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	applicationAutoScalingSvc, err := getApplicationAutoScalingClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all tables
	tables, marker, err := listTables(dynamoDBSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(tables))
	for i, table := range tables {
		dynamoDBTable, err := buildDynamoDBTableSnapshot(dynamoDBSvc, applicationAutoScalingSvc, table)
		if err != nil {
			zap.L().Debug("error occurred building snapshot", zap.Int("table number", i))
			return nil, nil, err
		}
		if dynamoDBTable == nil {
			continue
		}
		dynamoDBTable.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		dynamoDBTable.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      dynamoDBTable,
			ID:              *dynamoDBTable.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.DynamoDBTableSchema,
		})
	}

	return resources, marker, nil
}
