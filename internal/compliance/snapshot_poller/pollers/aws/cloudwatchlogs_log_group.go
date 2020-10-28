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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	CloudWatchLogsClientFunc = setupCloudWatchLogsClient
)

// FIXME: this low batch size means we may be better off just initiating a series of single resource
// 	scans spread out over several minutes instead of trying to batch 10 at a time, as even this very
//	low batch size may cause rate limiting issues.
const cloudwatchlogsBatchSize = 10

func setupCloudWatchLogsClient(sess *session.Session, cfg *aws.Config) interface{} {
	return cloudwatchlogs.New(sess, cfg)
}

func getCloudWatchLogsClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (cloudwatchlogsiface.CloudWatchLogsAPI, error) {

	client, err := getClient(pollerResourceInput, CloudWatchLogsClientFunc, "cloudwatchlogs", region)
	if err != nil {
		return nil, err
	}

	return client.(cloudwatchlogsiface.CloudWatchLogsAPI), nil
}

// PollCloudWatchLogsLogGroup polls a single CloudWatchLogs LogGroup resource
func PollCloudWatchLogsLogGroup(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry) (resource interface{}, err error) {

	cwClient, err := getCloudWatchLogsClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	// See PollCloudFormationStack for a detailed reasoning behind these actions
	// Get just the resource portion of the ARN, drop the resource type prefix
	lgResource := strings.TrimPrefix(resourceARN.Resource, "log-group:")

	// Split out the log group name from any additional modifiers
	lgName := strings.Split(lgResource, ":")[0]
	logGroup, err := getLogGroup(cwClient, lgName)
	if logGroup == nil || err != nil {
		// this can happen in case we didn't find the requested log group - it might have been deleted
		// or we might have encountered some issue with querying for it
		return nil, err
	}
	snapshot, err := buildCloudWatchLogsLogGroupSnapshot(cwClient, logGroup)
	if err != nil {
		return nil, err
	}
	snapshot.Region = &resourceARN.Region
	snapshot.AccountID = &resourceARN.AccountID
	scanRequest.ResourceID = snapshot.ARN
	return snapshot, nil
}

// getLogGroup returns a specific cloudwatch logs log group
func getLogGroup(svc cloudwatchlogsiface.CloudWatchLogsAPI, logGroupName string) (*cloudwatchlogs.LogGroup, error) {
	logGroups, err := svc.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: &logGroupName,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "CloudWatchLogs.DescribeLogGroups: %s", logGroupName)
	}

	for _, logGroup := range logGroups.LogGroups {
		if *logGroup.LogGroupName == logGroupName {
			return logGroup, nil
		}
	}

	zap.L().Warn("tried to scan non-existent resource",
		zap.String("resource", logGroupName),
		zap.String("resourceType", awsmodels.CloudWatchLogGroupSchema))
	return nil, nil
}

// describeLogGroups returns all Log Groups in the account
func describeLogGroups(cloudwatchLogsSvc cloudwatchlogsiface.CloudWatchLogsAPI, nextMarker *string) (
	logGroups []*cloudwatchlogs.LogGroup, marker *string, err error) {
	// CloudWatch log groups have fairly absurdly low throttling limits, so intentionally choke this
	// down super slow to avoid going over.
	err = cloudwatchLogsSvc.DescribeLogGroupsPages(&cloudwatchlogs.DescribeLogGroupsInput{
		Limit:     aws.Int64(cloudwatchlogsBatchSize),
		NextToken: nextMarker,
	},
		func(page *cloudwatchlogs.DescribeLogGroupsOutput, lastPage bool) bool {
			return loggroupIterator(page, &logGroups, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "CloudWatchLogs.DescribeLogGroups")
	}
	return
}

func loggroupIterator(page *cloudwatchlogs.DescribeLogGroupsOutput, logGroups *[]*cloudwatchlogs.LogGroup, marker **string) bool {
	*logGroups = append(*logGroups, page.LogGroups...)
	*marker = page.NextToken
	return len(*logGroups) < cloudwatchlogsBatchSize
}

// listTagsLogGroup returns the tags for a given log group
//
// This API call throttles if more than 10 are made in the same region in the same ~100 ms. Not
// documented anywhere, just determined by Science.
func listTagsLogGroup(svc cloudwatchlogsiface.CloudWatchLogsAPI, groupName *string) (map[string]*string, error) {
	tags, err := svc.ListTagsLogGroup(&cloudwatchlogs.ListTagsLogGroupInput{
		LogGroupName: groupName,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "CloudWatchLogs.ListTagsLogGroup: %s", aws.StringValue(groupName))
	}
	return tags.Tags, nil
}

// buildCloudWatchLogsLogGroupSnapshot returns a complete snapshot of a LogGroup
func buildCloudWatchLogsLogGroupSnapshot(
	svc cloudwatchlogsiface.CloudWatchLogsAPI,
	logGroup *cloudwatchlogs.LogGroup,
) (*awsmodels.CloudWatchLogsLogGroup, error) {

	logGroupSnapshot := &awsmodels.CloudWatchLogsLogGroup{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   logGroup.Arn,
			ResourceType: aws.String(awsmodels.CloudWatchLogGroupSchema),
			// Convert milliseconds to seconds before converting to datetime
			// loses nanosecond precision
			TimeCreated: utils.UnixTimeToDateTime(*logGroup.CreationTime / 1000),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name: logGroup.LogGroupName,
			ARN:  logGroup.Arn,
		},
		KmsKeyId:          logGroup.KmsKeyId,
		MetricFilterCount: logGroup.MetricFilterCount,
		RetentionInDays:   logGroup.RetentionInDays,
		StoredBytes:       logGroup.StoredBytes,
	}
	var err error
	logGroupSnapshot.Tags, err = listTagsLogGroup(svc, logGroupSnapshot.Name)
	if err != nil {
		return nil, err
	}

	return logGroupSnapshot, nil
}

// PollCloudWatchLogsLogGroups gathers information on each CloudWatchLogs LogGroup for an AWS account
func PollCloudWatchLogsLogGroups(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting CloudWatch LogGroup resource poller")

	cloudwatchLogGroupSvc, err := getCloudWatchLogsClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all log groups
	logGroups, marker, err := describeLogGroups(cloudwatchLogGroupSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(logGroups))
	for i, logGroup := range logGroups {
		logGroupSnapshot, err := buildCloudWatchLogsLogGroupSnapshot(cloudwatchLogGroupSvc, logGroup)
		if err != nil {
			zap.L().Debug("error occurred building snapshot", zap.Int("loggroup number", i))
			return nil, nil, err
		}
		logGroupSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		logGroupSnapshot.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      logGroupSnapshot,
			ID:              *logGroupSnapshot.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.CloudWatchLogGroupSchema,
		})
	}

	return resources, marker, nil
}
