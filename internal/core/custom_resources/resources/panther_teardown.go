package resources

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
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const globalLayerName = "panther-engine-globals"

type PantherTeardownProperties struct {
	CustomResourceLogGroupName string `validate:"required"`
	CustomResourceRoleName     string `validate:"required"`
	EcrRepoName                string
}

func customPantherTeardown(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const resourceID = "custom:panther-teardown:singleton"

	switch event.RequestType {
	case cfn.RequestDelete:
		var props PantherTeardownProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return resourceID, nil, err
		}

		if props.EcrRepoName != "" {
			if err := destroyEcrRepo(props.EcrRepoName); err != nil {
				return resourceID, nil, err
			}
		}

		if err := destroyLambdaLayers(); err != nil {
			return resourceID, nil, err
		}

		// Save the log groups for last
		return resourceID, nil, destroyLogGroups(props.CustomResourceLogGroupName, props.CustomResourceRoleName)

	default:
		// skip creates/updates
		return resourceID, nil, nil
	}
}

// ECR repos can't be deleted by CloudFormation unless they are empty.
func destroyEcrRepo(repoName string) error {
	zap.L().Info("removing ECR repository", zap.String("repo", repoName))
	_, err := ecrClient.DeleteRepository(&ecr.DeleteRepositoryInput{
		// Force:true to remove images as well (easier than emptying the repo explicitly)
		Force:          aws.Bool(true),
		RepositoryName: &repoName,
	})

	var awsErr awserr.Error
	if errors.As(err, &awsErr) && awsErr.Code() == ecr.ErrCodeRepositoryNotFoundException {
		// repo doesn't exist - that's fine, nothing to do here
		err = nil
	}
	return err
}

// Remove layers created for the policy and rules engines
func destroyLambdaLayers() error {
	versions, err := lambdaClient.ListLayerVersions(
		&lambda.ListLayerVersionsInput{LayerName: aws.String(globalLayerName)})
	if err != nil {
		return fmt.Errorf("failed to remove layer %s: %v", globalLayerName, err)
	}

	for _, version := range versions.LayerVersions {
		_, err := lambdaClient.DeleteLayerVersion(&lambda.DeleteLayerVersionInput{
			LayerName:     aws.String(globalLayerName),
			VersionNumber: version.Version,
		})
		if err != nil {
			return fmt.Errorf("failed to delete layer version %d: %v", aws.Int64Value(version.Version), err)
		}
	}

	return nil
}

// Remove leftover CloudWatch log groups.
//
// "/aws/lambda/panther-" log groups are often recreated by still-running Lambda functions shortly
// after CloudFormation deletes them.
// This is problematic because it will break future deploys - CFN refuses to create log groups which already exist.
func destroyLogGroups(selfLogGroupName, roleName string) error {
	listInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String("/aws/lambda/panther-"),
	}

	// Find and remove all "/aws/lambda/panther-*" log groups except the one used by this function.
	var groupNames []*string
	err := cloudWatchLogsClient.DescribeLogGroupsPages(listInput, func(page *cloudwatchlogs.DescribeLogGroupsOutput, _ bool) bool {
		for _, group := range page.LogGroups {
			if group.LogGroupName != nil && *group.LogGroupName != selfLogGroupName {
				groupNames = append(groupNames, group.LogGroupName)
			}
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("failed to list log groups: %v", err)
	}

	// By the time this code runs, all other Lambda functions and non-bootstrap stacks have been gone
	// for some time, so we should be able to remove the leftover groups without worrying about more pending logs.
	for _, name := range groupNames {
		if err := deleteLogGroup(name); err != nil {
			return err
		}
	}

	// Now for the tricky part - how to remove our own log group?
	// If we just delete the group, it will be recreated automatically when the Lambda function exits.
	// To prevent this, we use an IAM permission boundary to block future log writes from our own IAM role.
	// Then we can let CFN delete the log group and Lambda will not be allowed to recreate it.

	zap.L().Info("blocking future log writes")
	_, err = iamClient.PutRolePermissionsBoundary(&iam.PutRolePermissionsBoundaryInput{
		PermissionsBoundary: aws.String("arn:aws:iam::aws:policy/AWSDenyAll"),
		RoleName:            &roleName,
	})
	if err != nil {
		return fmt.Errorf("failed to add iam permission boundary to self: %v", err)
	}

	time.Sleep(15 * time.Second) // takes a few seconds for IAM boundary to kick in

	// Our own log group will be deleted by CloudFormation right after we exit.
	return nil
}

func deleteLogGroup(name *string) error {
	zap.L().Info("deleting log group", zap.String("groupName", *name))
	_, err := cloudWatchLogsClient.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{LogGroupName: name})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == cloudwatchlogs.ErrCodeResourceNotFoundException {
			// log group no longer exists, carry on
			return nil
		}
		return fmt.Errorf("failed to delete log group %s: %v", *name, err)
	}

	return nil
}
