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
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	"go.uber.org/zap"
)

type StackSetProperties struct {
	AccountID         string                      `validate:"required,len=12"`
	AdminRoleArn      string                      `validate:"required"`
	ExecutionRoleName string                      `validate:"required"`
	Parameters        []*cloudformation.Parameter `validate:"omitempty,dive,required"`
	StackSetName      string                      `validate:"required"`
	TemplateURL       string                      `validate:"required"`
}

// Deploys a stack set with an instance in a single region
func customStackSet(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props StackSetProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		resourceID := fmt.Sprintf("custom:stackset:%s:%s:%s",
			*getSession().Config.Region, props.AccountID, props.StackSetName)
		return resourceID, nil, deployStackSet(props)

	case cfn.RequestDelete:
		split := strings.Split(event.PhysicalResourceID, ":")
		if len(split) < 5 {
			// invalid resourceID, skip delete
			return event.PhysicalResourceID, nil, nil
		}

		return event.PhysicalResourceID, nil, deleteStackSet(split[3], split[4])

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

// Returns once parent stack set has started creation (does not wait for it to finish).
func deployStackSet(props StackSetProperties) error {
	zap.L().Info("deploying stack set", zap.String("name", props.StackSetName))
	cfClient := getCloudFormationClient()

	alreadyExists := func(err error) bool {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudformation.ErrCodeNameAlreadyExistsException {
			return true
		}
		return false
	}

	stackSetInput := &cloudformation.CreateStackSetInput{
		AdministrationRoleARN: &props.AdminRoleArn,
		ExecutionRoleName:     &props.ExecutionRoleName,
		Parameters:            props.Parameters,
		StackSetName:          &props.StackSetName,
		Tags: []*cloudformation.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("Panther"),
			},
		},
		TemplateURL: &props.TemplateURL,
	}
	_, err := cfClient.CreateStackSet(stackSetInput)
	if err != nil && !alreadyExists(err) {
		return fmt.Errorf("error creating stack set: %v", err)
	}

	stackSetInstancesInput := &cloudformation.CreateStackInstancesInput{
		Accounts: []*string{&props.AccountID},
		OperationPreferences: &cloudformation.StackSetOperationPreferences{
			FailureToleranceCount: aws.Int64(0),
			MaxConcurrentCount:    aws.Int64(1),
		},
		Regions:      []*string{getSession().Config.Region},
		StackSetName: &props.StackSetName,
	}
	_, err = cfClient.CreateStackInstances(stackSetInstancesInput)
	if err != nil && !alreadyExists(err) {
		return fmt.Errorf("error creating stack instance: %v", err)
	}

	return nil
}

// Delete a single CFN stack set.
//
// Waits for the stack instance in the current region to delete, then
// returns as soon as parent stack set starts deleting.
func deleteStackSet(accountID, stackSetName string) error {
	zap.L().Info("deleting CloudFormation stack set", zap.String("name", stackSetName))

	// First, delete the stack set *instance* in this region
	cfClient := getCloudFormationClient()
	_, err := cfClient.DeleteStackInstances(&cloudformation.DeleteStackInstancesInput{
		StackSetName: &stackSetName,
		Accounts:     []*string{&accountID},
		Regions:      []*string{getSession().Config.Region},
		RetainStacks: aws.Bool(false),
	})
	exists := true
	if err != nil {
		if stackSetDoesNotExistError(err) {
			exists, err = false, nil
		} else {
			return fmt.Errorf("failed to delete stack set instance: %v", err)
		}
	}

	// Wait for the delete to complete (required for deleting parent stack set)
	region := *getSession().Config.Region
	zap.L().Info("waiting for stack set instance to finish deleting")
	for ; exists && err == nil; exists, err = stackSetInstanceExists(cfClient, stackSetName, accountID, region) {
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return err
	}

	// Now delete the parent stack set (but don't wait for it to finish)
	if _, err := cfClient.DeleteStackSet(&cloudformation.DeleteStackSetInput{StackSetName: &stackSetName}); err != nil {
		if !stackSetDoesNotExistError(err) {
			return fmt.Errorf("failed to delete stack set: %v", err)
		}
	}

	return nil
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

// Return true if CF stack set exists
func stackSetInstanceExists(cfClient cloudformationiface.CloudFormationAPI, stackSetName, account, region string) (bool, error) {
	input := &cloudformation.DescribeStackInstanceInput{
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

	if status := aws.StringValue(response.StackInstance.Status); status == cloudformation.StackInstanceStatusInoperable {
		return false, fmt.Errorf("%s stack set instance is %s and will have to be deleted manually: %s",
			stackSetName, status, aws.StringValue(response.StackInstance.StatusReason))
	}

	return true, nil
}
