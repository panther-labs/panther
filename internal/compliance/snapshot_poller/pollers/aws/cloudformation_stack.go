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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

const (
	// Time to delay the requeue of a scan of a CloudFormation stack whose drift detection was in
	// progress when this scan started.
	driftDetectionRequeueDelaySeconds = 30
	requeueRequiredError              = "CloudFormation: re-queue required"
)

var (
	// Set as variables to be overridden in testing
	CloudFormationClientFunc = setupCloudFormationClient
	maxDriftDetectionBackoff = 2 * time.Minute
)

func setupCloudFormationClient(sess *session.Session, cfg *aws.Config) interface{} {
	return cloudformation.New(sess, cfg)
}

func getCloudFormationClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (cloudformationiface.CloudFormationAPI, error) {

	client, err := getClient(pollerResourceInput, CloudFormationClientFunc, "cloudformation", region)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	return client.(cloudformationiface.CloudFormationAPI), nil
}

// PollCloudFormationStack polls a single CloudFormation stack resource
func PollCloudFormationStack(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	cfClient, err := getCloudFormationClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	// Although CloudFormation API calls may take either an ARN or name in most cases, we must use
	// the name here as we do not always get the full ARN from the event processor, we may be missing
	// the 'additional identifiers' portion. This can lead to problems differentiating between live
	// and deleted stacks with the same name, but we shouldn't have to worry about that as we don't
	// need to scan deleted stacks.

	// Get just the resource portion of the ARN, and drop the resource type prefix
	resource := strings.TrimPrefix(resourceARN.Resource, "stack/")
	// Split out the stack name from any additional modifiers, and just keep the actual name
	stackName := strings.Split(resource, "/")[0]

	driftID, err := detectStackDrift(cfClient, aws.String(stackName))
	if err != nil {
		if err.Error() == requeueRequiredError {
			utils.Requeue(pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{
					scanRequest,
				},
			}, driftDetectionRequeueDelaySeconds)
		}
		return nil, nil
	}

	if driftID != nil {
		waitForStackDriftDetection(cfClient, driftID)
	}

	stack := getStack(cfClient, stackName)

	snapshot := buildCloudFormationStackSnapshot(cfClient, stack)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	// We need to do this in case the resourceID passed in was missing the additional identifiers
	scanRequest.ResourceID = snapshot.ARN
	return snapshot, nil
}

// getStack returns a specific CloudFormation stack
func getStack(svc cloudformationiface.CloudFormationAPI, stackName string) *cloudformation.Stack {
	stack, err := svc.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Message() == "Stack with id "+stackName+" does not exist" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", stackName),
					zap.String("resourceType", awsmodels.CloudFormationStackSchema))
				return nil
			}
		}
		utils.LogAWSError("CloudFormation.DescribeStacks", err)
		return nil
	}
	return stack.Stacks[0]
}

// describeStacks returns all CloudFormation stacks in the account
func describeStacks(cloudformationSvc cloudformationiface.CloudFormationAPI) (stacks []*cloudformation.Stack, err error) {
	err = cloudformationSvc.DescribeStacksPages(&cloudformation.DescribeStacksInput{},
		func(page *cloudformation.DescribeStacksOutput, lastPage bool) bool {
			stacks = append(stacks, page.Stacks...)
			return true
		})

	if err != nil {
		return nil, errors.Wrap(err, "CloudFormation.DescribeStacksPages")
	}
	return stacks, nil
}

// detectStackDrift initiates the stack drift detection process, which may take several minutes to complete
func detectStackDrift(cloudformationSvc cloudformationiface.CloudFormationAPI, arn *string) (*string, error) {
	detectionID, err := cloudformationSvc.DetectStackDrift(
		&cloudformation.DetectStackDriftInput{StackName: arn},
	)

	if err == nil {
		return detectionID.StackDriftDetectionId, nil
	}

	awsErr, ok := err.(awserr.Error)
	if !ok || awsErr.Code() != "ValidationError" {
		// Run of the mill error, stop scanning this resource
		utils.LogAWSError("CloudFormation.DetectStackDrift", err)
		return nil, err
	}

	// A ValidationError could be several things, which have different meanings for us
	if strings.HasPrefix(awsErr.Message(), "Drift detection is already in progress for stack") {
		// We cannot continue scanning this resource, we must re-queue the scan
		zap.L().Debug("CloudFormation: stack drift detection already in progress", zap.String("stack ARN", *arn))
		return nil, errors.New(requeueRequiredError)
	}

	// We can continue scanning this resource, but it will not have drift detection info
	zap.L().Debug("CloudFormation: stack drift detection cannot complete due to stack state", zap.String("stack ARN", *arn))
	return nil, nil
}

// describeStackResourceDrifts returns the drift status for each resource in a stack
func describeStackResourceDrifts(
	cloudformationSvc cloudformationiface.CloudFormationAPI, stackId *string) (drifts []*cloudformation.StackResourceDrift) {

	err := cloudformationSvc.DescribeStackResourceDriftsPages(&cloudformation.DescribeStackResourceDriftsInput{StackName: stackId},
		func(page *cloudformation.DescribeStackResourceDriftsOutput, lastPage bool) bool {
			drifts = append(drifts, page.StackResourceDrifts...)
			return true
		})
	if err != nil {
		utils.LogAWSError("CloudFormation.DescribeStackResourceDriftsPages", err)
	}
	return
}

// buildCloudFormationStackSnapshot returns a complete snapshot of an ACM certificate
func buildCloudFormationStackSnapshot(
	cloudformationSvc cloudformationiface.CloudFormationAPI,
	stack *cloudformation.Stack,
) *awsmodels.CloudFormationStack {

	if stack == nil {
		return nil
	}

	stackSnapshot := &awsmodels.CloudFormationStack{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   stack.StackId,
			ResourceType: aws.String(awsmodels.CloudFormationStackSchema),
			TimeCreated:  utils.DateTimeFormat(*stack.CreationTime),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  stack.StackId,
			Name: stack.StackName,
			ID:   stack.StackId,
		},
		Capabilities:                stack.Capabilities,
		ChangeSetId:                 stack.ChangeSetId,
		DeletionTime:                stack.DeletionTime,
		Description:                 stack.Description,
		DisableRollback:             stack.DisableRollback,
		DriftInformation:            stack.DriftInformation,
		EnableTerminationProtection: stack.EnableTerminationProtection,
		LastUpdatedTime:             stack.LastUpdatedTime,
		NotificationARNs:            stack.NotificationARNs,
		Outputs:                     stack.Outputs,
		Parameters:                  stack.Parameters,
		ParentId:                    stack.ParentId,
		RoleARN:                     stack.RoleARN,
		RollbackConfiguration:       stack.RollbackConfiguration,
		RootId:                      stack.RootId,
		StackStatus:                 stack.StackStatus,
		StackStatusReason:           stack.StackStatusReason,
		TimeoutInMinutes:            stack.TimeoutInMinutes,
	}

	stackSnapshot.Tags = utils.ParseTagSlice(stack.Tags)

	stackSnapshot.Drifts = describeStackResourceDrifts(cloudformationSvc, stack.StackId)

	return stackSnapshot
}

// waitForStackDriftDetection blocks and only returns when a given stack drift detection is complete
func waitForStackDriftDetection(svc cloudformationiface.CloudFormationAPI, driftID *string) {
	statusIn := &cloudformation.DescribeStackDriftDetectionStatusInput{
		StackDriftDetectionId: driftID,
	}
	detectDriftStatus := func() error {
		driftOut, driftErr := svc.DescribeStackDriftDetectionStatus(statusIn)
		if driftErr != nil {
			return backoff.Permanent(driftErr)
		}
		if *driftOut.DetectionStatus == "DETECTION_IN_PROGRESS" {
			return errors.New("stack detection in progress")
		}
		return nil
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxElapsedTime = maxDriftDetectionBackoff
	backoffErr := backoff.Retry(detectDriftStatus, expBackoff)
	if backoffErr != nil {
		utils.LogAWSError("CloudFormation.DescribeStackDriftDetectionStatus", backoffErr)
	}
}

// PollCloudFormationStacks gathers information on each CloudFormation Stack for an AWS account.
func PollCloudFormationStacks(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting CloudFormation Stack resource poller")
	cloudformationStackSnapshots := make(map[string]*awsmodels.CloudFormationStack)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "cloudformation") {
		cloudformationSvc, err := getCloudFormationClient(pollerInput, *regionID)
		if err != nil {
			return nil, err // error is logged in getClient()
		}

		// Start with generating a list of all stacks
		stacks, err := describeStacks(cloudformationSvc)
		if err != nil {
			return nil, errors.Wrapf(err, "PollCloudFormationStacks(%#v) in region %s", *pollerInput, *regionID)
		}
		if len(stacks) == 0 {
			zap.L().Debug("no CloudFormation stacks found", zap.String("region", *regionID))
			continue
		}

		// List of stack drift detection statuses
		stackDriftDetectionIds := make(map[string]*string)
		ignoredIds := make(map[string]bool)
		var requeueIds []*string

		// Kick off the stack drift detections
		for _, stack := range stacks {
			driftID, err := detectStackDrift(cloudformationSvc, stack.StackId)
			if err == nil {
				if driftID != nil {
					// The drift detection worked properly
					stackDriftDetectionIds[*stack.StackId] = driftID
				}
				// Implicit case: the drift detection was unable to complete due to the state of the
				// stack, continue on building this resource without stack drift detection
			} else {
				// Failed resources are always dropped
				ignoredIds[*stack.StackId] = true
				if err.Error() == requeueRequiredError {
					// The drift detection did not work, and we must re-queue a scan for this message
					requeueIds = append(requeueIds, stack.StackId)
				}
			}
		}

		// Construct one re-scan request for all the stacks that need to be re-scanned and send it
		if len(requeueIds) > 0 {
			scanRequest := pollermodels.ScanMsg{}
			for _, stackId := range requeueIds {
				scanRequest.Entries = append(scanRequest.Entries, &pollermodels.ScanEntry{
					AWSAccountID:     &pollerInput.AuthSourceParsedARN.AccountID,
					IntegrationID:    pollerInput.IntegrationID,
					ResourceID:       stackId,
					ResourceType:     aws.String(awsmodels.CloudFormationStackSchema),
					ScanAllResources: aws.Bool(false),
				})
			}
			utils.Requeue(scanRequest, driftDetectionRequeueDelaySeconds)
		}

		// Wait for all stack drift detections to be complete
		for _, driftID := range stackDriftDetectionIds {
			waitForStackDriftDetection(cloudformationSvc, driftID)
		}

		// Now that the stacks have their full drift information, describe them again
		updatedStacks, err := describeStacks(cloudformationSvc)
		if err != nil {
			return nil, errors.Wrapf(err, "PollCloudFormationStacks(%#v) in region %s", *pollerInput, *regionID)
		}

		// Build the stack snapshots
		for _, stack := range updatedStacks {
			// Check if this stack failed an earlier part of the scan
			if ignoredIds[*stack.StackId] {
				continue
			}

			// As of 2019/11/12, the cloudformation describe-stacks API call does not return
			// termination protection information unless a stack name is specified. I suspect this
			// is a bug/unintended behavior in the AWS API
			fullStack := getStack(cloudformationSvc, *stack.StackName)
			cfnStackSnapshot := buildCloudFormationStackSnapshot(cloudformationSvc, fullStack)
			if cfnStackSnapshot == nil {
				continue
			}

			// Set meta data not known directly by the stack
			cfnStackSnapshot.Region = regionID
			cfnStackSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

			if _, ok := cloudformationStackSnapshots[*stack.StackId]; !ok {
				cloudformationStackSnapshots[*stack.StackId] = cfnStackSnapshot
			} else {
				zap.L().Info(
					"overwriting existing CloudFormation Stack snapshot",
					zap.String("resourceId", *stack.StackId),
				)
				cloudformationStackSnapshots[*stack.StackId] = cfnStackSnapshot
			}
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(cloudformationStackSnapshots))
	for resourceID, cloudformationSnapshot := range cloudformationStackSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      cloudformationSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.CloudFormationStackSchema,
		})
	}

	return resources, nil
}
