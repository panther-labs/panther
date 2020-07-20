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

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	CloudWatchLogsClientFunc = setupCloudWatchLogsClient
)

func setupCloudWatchLogsClient(sess *session.Session, cfg *aws.Config) interface{} {
	return cloudwatchlogs.New(sess, cfg)
}

func getCloudWatchLogsClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (cloudwatchlogsiface.CloudWatchLogsAPI, error) {

	client, err := getClient(pollerResourceInput, CloudWatchLogsClientFunc, "cloudwatchlogs", region)
	if err != nil {
		return nil, err // error is logged in getClient()
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
	if err != nil {
		return nil, err
	}
	if logGroup == nil {
		// this can happen in case we didn't find the requested log group - it might have been deleted
		return nil, nil
	}
	snapshot := buildCloudWatchLogsLogGroupSnapshot(cwClient, logGroup)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	scanRequest.ResourceID = snapshot.ARN
	return snapshot, nil
}

// getLogGroup returns a specific cloudwatch logs log group
func getLogGroup(svc cloudwatchlogsiface.CloudWatchLogsAPI, logGroupName string) (*cloudwatchlogs.LogGroup, error) {
	logGroups, err := svc.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: &logGroupName,
	})
	if err != nil {
		utils.LogAWSError("CloudWatchLogs.DescribeLogGroups", err)
		return nil, err
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
func describeLogGroups(cloudwatchLogsSvc cloudwatchlogsiface.CloudWatchLogsAPI) (logGroups []*cloudwatchlogs.LogGroup, err error) {
	err = cloudwatchLogsSvc.DescribeLogGroupsPages(&cloudwatchlogs.DescribeLogGroupsInput{},
		func(page *cloudwatchlogs.DescribeLogGroupsOutput, lastPage bool) bool {
			logGroups = append(logGroups, page.LogGroups...)
			return true
		})
	if err != nil {
		return nil, errors.Wrap(err, "CloudWatchLogs.DescribeLogGroups")
	}
	return
}

// listTagsLogGroup returns the tags for a given log group
func listTagsLogGroup(svc cloudwatchlogsiface.CloudWatchLogsAPI, groupName *string) map[string]*string {
	tags, err := svc.ListTagsLogGroup(&cloudwatchlogs.ListTagsLogGroupInput{
		LogGroupName: groupName,
	})
	if err != nil {
		utils.LogAWSError("CloudWatchLogs ListTagsLogGroup", err)
		return nil
	}
	return tags.Tags
}

// buildCloudWatchLogsLogGroupSnapshot returns a complete snapshot of a LogGroup
func buildCloudWatchLogsLogGroupSnapshot(
	svc cloudwatchlogsiface.CloudWatchLogsAPI,
	logGroup *cloudwatchlogs.LogGroup,
) *awsmodels.CloudWatchLogsLogGroup {

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
	logGroupSnapshot.Tags = listTagsLogGroup(svc, logGroupSnapshot.Name)

	return logGroupSnapshot
}

// PollCloudWatchLogsLogGroups gathers information on each CloudWatchLogs LogGroup for an AWS account
func PollCloudWatchLogsLogGroups(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting CloudWatch LogGroup resource poller")
	logGroupSnapshots := make(map[string]*awsmodels.CloudWatchLogsLogGroup)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "logs") {
		cloudwatchLogGroupSvc, err := getCloudWatchLogsClient(pollerInput, *regionID)
		if err != nil {
			return nil, err // error is logged in getClient()
		}

		// Start with generating a list of all log groups
		logGroups, err := describeLogGroups(cloudwatchLogGroupSvc)
		if err != nil {
			return nil, errors.Wrapf(err, "PollCloudWatchLogsLogGroups(%#v) in region %s", *pollerInput, *regionID)
		}
		if len(logGroups) == 0 {
			zap.L().Debug("no CloudWatchLogs LogGroups found", zap.String("region", *regionID))
			continue
		}

		for _, logGroup := range logGroups {
			logGroupSnapshot := buildCloudWatchLogsLogGroupSnapshot(cloudwatchLogGroupSvc, logGroup)
			if logGroupSnapshot == nil {
				continue
			}
			logGroupSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			logGroupSnapshot.Region = regionID

			if _, ok := logGroupSnapshots[*logGroupSnapshot.ARN]; !ok {
				logGroupSnapshots[*logGroup.Arn] = logGroupSnapshot
			} else {
				zap.L().Info(
					"overwriting existing CloudWatchLogs LogGroup snapshot",
					zap.String("resourceId", *logGroupSnapshot.ARN),
				)
				logGroupSnapshots[*logGroupSnapshot.ARN] = logGroupSnapshot
			}
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(logGroupSnapshots))
	for resourceID, logGroupSnapshot := range logGroupSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      logGroupSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.CloudWatchLogGroupSchema,
		})
	}

	return resources, nil
}
