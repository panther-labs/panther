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
	err := walkPantherStack(cfnClient, aws.String(bootstrapStack), func(r cfnResource) {
		if aws.StringValue(r.Resource.ResourceType) == "AWS::ECS::Cluster" {
			clusterInBootstrap = true
		}
	})
	if err != nil {
		// err == nil if the stack does not yet exist
		logger.Fatalf("failed to walk bootstrap stack: %v", err)
	}
	if clusterInBootstrap {
		// To delete the ECS cluster from bootstrap, the entire web stack has to be deleted first.
		// There is no user data that needs to be preserved in that stack - it's stateless.
		logger.Infof("migration: deleting stack %s so ECS::Cluster can be migrated out of %s",
			frontendStack, bootstrapStack)
		if err = deleteStack(cfnClient, aws.String(frontendStack)); err != nil {
			logger.Fatalf("failed to delete %s: %v", frontendStack, err)
		}
	}

	// In v1.4.0, the self-onboarding stackset was replaced with a simple nested template.
	if err := deleteStackSet(cfnClient, &accountID, aws.String(realTimeEventsStackSet)); err != nil {
		logger.Fatal(err)
	}
}

// Delete a single CFN stack set and wait for it to finish (only deletes stack instances from current region)
func deleteStackSet(client *cfn.CloudFormation, accountID, stackSet *string) error {
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
			return fmt.Errorf("failed to delete %s stack set instance in %s: %v", *stackSet, *client.Config.Region, err)
		}
	}

	// Wait for the delete to complete
	if exists {
		logger.Infof("migration: deleting stack set %s (will be replaced in onboard stack)", *stackSet)
	}
	for ; exists && err == nil; exists, err = stackSetInstanceExists(client, *stackSet, *accountID, *client.Config.Region) {
		time.Sleep(pollInterval)
	}
	if err != nil {
		return err
	}

	// Now delete the parent stack set
	if _, err := client.DeleteStackSet(&cfn.DeleteStackSetInput{StackSetName: stackSet}); err != nil {
		if stackSetDoesNotExistError(err) {
			exists = false
		} else {
			return fmt.Errorf("failed to delete %s stack set in %s: %v", *stackSet, *client.Config.Region, err)
		}
	}

	// Wait for the delete to complete
	logger.Debugf("waiting for stack set to finish deleting")
	for ; exists && err == nil; exists, err = stackSetExists(client, *stackSet) {
		time.Sleep(pollInterval)
	}

	return err
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
