package mage

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
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
)

const (
	// Removed stacks
	alarmsStack            = "panther-cw-alarms"
	metricFilterStack      = "panther-cw-metric-filters"
	realTimeEventsStackSet = "panther-real-time-events"
)

// Migrations which run before the main deploy.
//
// These can be removed a few releases after they have been added.
func migrate(awsSession *session.Session, accountID string) {
	cfnClient := cfn.New(awsSession)

	// In v1.3.0, the metric filter stack was replaced with custom resources.
	if err := deleteStack(cfnClient, aws.String(metricFilterStack)); err != nil {
		logger.Warnf("failed to delete deprecated %s stack: %v", metricFilterStack, err)
	}

	// In v1.4.0, the alarms stack was replaced with custom resources.
	if err := deleteStack(cfnClient, aws.String(alarmsStack)); err != nil {
		logger.Warnf("failed to delete deprecated %s stack: %v", alarmsStack, err)
	}

	// In v1.4.0, the ECS cluster moved from the bootstrap stack to the web stack.
	// Enumerate the bootstrap stack to see if this migration is necessary.
	clusterInBootstrap := false
	listStackResources(cfnClient, aws.String(bootstrapStack), func(r *cfn.StackResourceSummary) bool {
		if *r.ResourceType == "AWS::ECS::Cluster" {
			clusterInBootstrap = true
			return false // stop iterating
		}
		return true
	})

	if clusterInBootstrap {
		// To delete the ECS cluster from bootstrap, the entire web stack has to be deleted first.
		// There is no user data that needs to be preserved in that stack - it's stateless.
		logger.Infof("migration: deleting stack %s so ECS::Cluster can be migrated out of %s",
			frontendStack, bootstrapStack)
		if err := deleteStack(cfnClient, aws.String(frontendStack)); err != nil {
			logger.Fatalf("failed to delete %s: %v", frontendStack, err)
		}
	}

	// In v1.4.0, the self-onboarding stackset was replaced with a simple nested template.
	instanceErr, parentErr := deleteStackSet(cfnClient, &accountID, aws.String(realTimeEventsStackSet))
	if instanceErr != nil {
		// We have to delete the stack set instance in the deployment region because the onboard
		// stack will re-create the cloud security / log processing IAM roles with the same name as before.
		logger.Fatalf("failed to delete stack set instance %s in %s: %v",
			realTimeEventsStackSet, *awsSession.Config.Region, instanceErr)
	}
	if parentErr != nil {
		// If there are stack instances in other regions, the top-level stack set delete will fail, which
		// is ok - we'll just log a warning and continue. The IAM roles we care about should have been deleted.
		logger.Warnf("failed to delete stack set %s: %v", realTimeEventsStackSet, parentErr)
	}

	// In v1.4.0, the LogProcessingRole in onboard.yml was replaced with a reference to an aux template.
	// CF would try to delete and create an IAM role with the same name at the same time, causing a conflict.
	// I tried deleting just the IAM role in this migration, but CF still failed because it thought
	// the resource still existed in the stack. So we need to delete the entire onboard stack.
	//
	// This means Panther may miss a few S3 notifications (the SNS topic receiving S3 notifications
	// will be deleted), but only for its own audit log data and only for a few minutes.
	// Normal user data is not affected, only self-onboarding (S3 access logs, GuardDuty).
	// S3 should retry failed notifications for a short time in any case.
	oldLogRole := false
	listStackResources(cfnClient, aws.String(onboardStack), func(r *cfn.StackResourceSummary) bool {
		if *r.LogicalResourceId == "LogProcessingRole" && *r.ResourceType == "AWS::IAM::Role" {
			oldLogRole = true
			return false // stop iterating
		}
		return true
	})
	if oldLogRole {
		logger.Infof("migration: deleting stack %s (will be rebuilt)", onboardStack)
		if err := deleteStack(cfnClient, aws.String(onboardStack)); err != nil {
			logger.Fatalf("failed to delete %s: %v", onboardStack, err)
		}
	}

	// In v1.4.0, the CloudWatch dashboards changed their logicalIDs, so the stack needs to be
	// deleted before deploying or CF will fail with "dashboard already exists"
	oldDashboard := false
	listStackResources(cfnClient, aws.String(dashboardStack), func(r *cfn.StackResourceSummary) bool {
		if strings.HasSuffix(*r.LogicalResourceId, "AWSRegion") {
			oldDashboard = true
			return false // stop iterating
		}
		return true
	})
	if oldDashboard {
		logger.Infof("migration: deleting stack %s (will be rebuilt)", dashboardStack)
		if err := deleteStack(cfnClient, aws.String(dashboardStack)); err != nil {
			logger.Fatalf("failed to delete %s: %v", dashboardStack, err)
		}
	}
}

// Delete a CloudFormation stack set and wait for it to finish.
//
// Only deletes stack instances from the current region.
// Returns (stack instance error, parent stack set error)
func deleteStackSet(client *cfn.CloudFormation, accountID, stackSet *string) (error, error) {
	logger.Debugf("deleting CloudFormation stack set %s", *stackSet)

	// First, delete the stack set *instance* in this region
	_, err := client.DeleteStackInstances(&cfn.DeleteStackInstancesInput{
		StackSetName: stackSet,
		Accounts:     []*string{accountID},
		Regions:      []*string{client.Config.Region},
		RetainStacks: aws.Bool(false),
	})
	exists := true
	if err != nil {
		if stackSetDoesNotExistError(err) {
			exists, err = false, nil
		} else {
			return err, nil
		}
	}

	// Wait for the delete to complete
	if exists {
		logger.Infof("migration: deleting stack set %s (resources will be re-added)", *stackSet)
	}
	for ; exists && err == nil; exists, err = stackSetInstanceExists(client, *stackSet, *accountID, *client.Config.Region) {
		time.Sleep(pollInterval)
	}
	if err != nil {
		return err, nil
	}

	// Now delete the parent stack set if possible
	if _, err := client.DeleteStackSet(&cfn.DeleteStackSetInput{StackSetName: stackSet}); err != nil {
		if stackSetDoesNotExistError(err) {
			exists = false
		} else {
			return nil, err
		}
	}

	// Wait for the delete to complete
	logger.Debugf("waiting for stack set to finish deleting")
	for ; exists && err == nil; exists, err = stackSetExists(client, *stackSet) {
		time.Sleep(pollInterval)
	}

	return nil, err
}

// Return true if CF stack set exists
func stackSetExists(cfClient *cfn.CloudFormation, stackSetName string) (bool, error) {
	input := &cfn.DescribeStackSetInput{StackSetName: aws.String(stackSetName)}
	_, err := cfClient.DescribeStackSet(input)
	if err != nil {
		if stackSetDoesNotExistError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Return true if CF stack set exists
func stackSetInstanceExists(cfClient *cfn.CloudFormation, stackSetName, account, region string) (bool, error) {
	input := &cfn.DescribeStackInstanceInput{
		StackSetName:         &stackSetName,
		StackInstanceAccount: &account,
		StackInstanceRegion:  &region,
	}
	response, err := cfClient.DescribeStackInstance(input)
	if err != nil {
		if stackSetDoesNotExistError(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to describe stack instance %s in %s: %v", stackSetName, region, err)
	}

	if status := aws.StringValue(response.StackInstance.Status); status == cfn.StackInstanceStatusInoperable {
		return false, fmt.Errorf("%s stack set instance is %s and will have to be deleted manually: %s",
			stackSetName, status, aws.StringValue(response.StackInstance.StatusReason))
	}

	return true, nil
}

// Returns true if the error is caused by a non-existent stack set / instance
func stackSetDoesNotExistError(err error) bool {
	// need to also check for "StackSetNotFoundException" if the containing stack set does not exist
	if awsErr, ok := err.(awserr.Error); ok &&
		(awsErr.Code() == "StackInstanceNotFoundException" || awsErr.Code() == "StackSetNotFoundException") {

		return true
	}
	return false
}
