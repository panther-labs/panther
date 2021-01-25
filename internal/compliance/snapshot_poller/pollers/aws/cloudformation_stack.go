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

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
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
		return nil, err
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
		return nil, err
	}

	// Although CloudFormation API calls may take either an ARN or name in most cases, we must use
	// the name here. This is because we do not always get the full ARN from the event processor, so
	// we may be missing the 'additional identifiers' portion. Using the name could lead to problems
	// differentiating between live and deleted stacks with the same name, but we shouldn't have to
	// worry about that as we don't currently scan deleted stacks.

	// Get just the resource portion of the ARN, and drop the resource type prefix
	resource := strings.TrimPrefix(resourceARN.Resource, "stack/")
	// Split out the stack name from any additional modifiers, and just keep the actual name
	stackName := strings.Split(resource, "/")[0]

	driftID, err := detectStackDrift(cfClient, aws.String(stackName))
	if err != nil {
		if err.Error() == requeueRequiredError {
			err = utils.Requeue(pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{
					scanRequest,
				},
			}, driftDetectionRequeueDelaySeconds)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	}

	if driftID != nil {
		waitForStackDriftDetection(cfClient, driftID)
	}

	stack, err := getStack(cfClient, stackName)
	if err != nil {
		return nil, err
	}

	snapshot, err := buildCloudFormationStackSnapshot(cfClient, stack)
	if err != nil || snapshot == nil {
		return nil, err
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	// We need to do this in case the resourceID that was passed in was missing the additional identifiers
	scanRequest.ResourceID = snapshot.ARN
	return snapshot, nil
}

// getStack returns a specific CloudFormation stack
func getStack(svc cloudformationiface.CloudFormationAPI, stackName string) (*cloudformation.Stack, error) {
	stack, err := svc.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Message() == "Stack with id "+stackName+" does not exist" {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", stackName),
				zap.String("resourceType", awsmodels.CloudFormationStackSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "CloudFormation.DescribeStacks: %s", stackName)
	}
	// When specifying a stack name, there cannot be more than one result. If there are zero results,
	// an error is returned above.
	return stack.Stacks[0], nil
}

// describeStacks returns all CloudFormation stacks in the account
func describeStacks(cloudformationSvc cloudformationiface.CloudFormationAPI, nextMarker *string) (
	stacks []*cloudformation.Stack, marker *string, err error) {

	err = cloudformationSvc.DescribeStacksPages(&cloudformation.DescribeStacksInput{
		NextToken: nextMarker,
	},
		func(page *cloudformation.DescribeStacksOutput, lastPage bool) bool {
			return stackIterator(page, &stacks, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "CloudFormation.DescribeStacksPages")
	}

	return
}

func stackIterator(page *cloudformation.DescribeStacksOutput, stacks *[]*cloudformation.Stack, marker **string) bool {
	*stacks = append(*stacks, page.Stacks...)
	*marker = page.NextToken
	return len(*stacks) < defaultBatchSize
}

// detectStackDrift initiates the stack drift detection process, which may take several minutes to complete
func detectStackDrift(cloudformationSvc cloudformationiface.CloudFormationAPI, arn *string) (*string, error) {
	detectionID, err := cloudformationSvc.DetectStackDrift(&cloudformation.DetectStackDriftInput{StackName: arn})
	if err == nil {
		return detectionID.StackDriftDetectionId, nil
	}

	var awsErr awserr.Error
	if !errors.As(err, &awsErr) || awsErr.Code() != "ValidationError" {
		// Run of the mill error, stop scanning this resource
		return nil, errors.Wrapf(err, "CloudFormation.DetectStackDrift: %s", aws.StringValue(arn))
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
	cloudformationSvc cloudformationiface.CloudFormationAPI, stackId *string) (drifts []*cloudformation.StackResourceDrift, err error) {

	err = cloudformationSvc.DescribeStackResourceDriftsPages(&cloudformation.DescribeStackResourceDriftsInput{StackName: stackId},
		func(page *cloudformation.DescribeStackResourceDriftsOutput, lastPage bool) bool {
			drifts = append(drifts, page.StackResourceDrifts...)
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "CloudFormation.DescribeStackResourceDriftsPages: %s", aws.StringValue(stackId))
	}
	return
}

// buildCloudFormationStackSnapshot returns a complete snapshot of CloudFormation stack
func buildCloudFormationStackSnapshot(
	cloudformationSvc cloudformationiface.CloudFormationAPI,
	stack *cloudformation.Stack,
) (*awsmodels.CloudFormationStack, error) {

	if stack == nil {
		return nil, nil
	}

	stackSnapshot := &awsmodels.CloudFormationStack{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   stack.StackId,
			ResourceType: aws.String(awsmodels.CloudFormationStackSchema),
			TimeCreated:  stack.CreationTime,
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

	var err error
	stackSnapshot.Drifts, err = describeStackResourceDrifts(cloudformationSvc, stack.StackId)
	if err != nil {
		return nil, err
	}

	return stackSnapshot, nil
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
//
// This scanner is a beast, tread carefully.
func PollCloudFormationStacks(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting CloudFormation Stack resource poller")
	cloudformationSvc, err := getCloudFormationClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all stacks
	stacks, marker, err := describeStacks(cloudformationSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// List of stack drift detection statuses
	stackDriftDetectionIds := make(map[string]*string)
	ignoredIds := make(map[string]bool)
	var requeueIds []*string

	// Initiate the stack drift detections
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
			} else {
				// To be in line with the policy of "whenever a resource fails to scan cancel the scan",
				// we should technically exit at this point. But this poller is so finicky that I worry
				// that might render it entirely inoperable. Putting this error message in to trigger
				// paging so we can track if it is actually a problem in practice. If not, we can add
				// the return here.
				zap.L().Error(
					"unable to perform stack drift detection",
					zap.String("stackID", *stack.StackId),
					zap.String("region", *pollerInput.Region),
				)
			}
		}
	}

	// Construct and send one re-scan request for all the stacks that need to be re-scanned
	if len(requeueIds) > 0 {
		scanRequest := pollermodels.ScanMsg{}
		for _, stackId := range requeueIds {
			scanRequest.Entries = append(scanRequest.Entries, &pollermodels.ScanEntry{
				AWSAccountID:            &pollerInput.AuthSourceParsedARN.AccountID,
				IntegrationID:           pollerInput.IntegrationID,
				ResourceID:              stackId,
				ResourceType:            aws.String(awsmodels.CloudFormationStackSchema),
				RegionIgnoreList:        pollerInput.RegionIgnoreList,
				ResourceRegexIgnoreList: pollerInput.ResourceRegexIgnoreList,
				ResourceTypeIgnoreList:  pollerInput.ResourceTypeIgnoreList,
			})
		}
		if err = utils.Requeue(scanRequest, driftDetectionRequeueDelaySeconds); err != nil {
			return nil, nil, err
		}
	}

	// Wait for all stack drift detections to be complete
	// TODO: Parallelize this and begin the next step for the stacks that complete
	for _, driftID := range stackDriftDetectionIds {
		waitForStackDriftDetection(cloudformationSvc, driftID)
	}

	// Build the stack snapshots
	resources := make([]apimodels.AddResourceEntry, 0, len(stacks))
	for _, stack := range stacks {
		// Check if this stack failed an earlier part of the scan
		if stack == nil || ignoredIds[aws.StringValue(stack.StackId)] {
			continue
		}

		// As of 2020/08/15, the cloudformation describe-stacks API call does not return
		// termination protection information unless a stack name is specified. I suspect this
		// is a bug/unintended behavior in the AWS API.
		//
		// Additionally, we want to update the stack drift information post stack drift detection
		// completion so we need to make a describe stack call anyways.
		fullStack, err := getStack(cloudformationSvc, *stack.StackName)
		if err != nil {
			return nil, nil, err
		}
		cfnStackSnapshot, err := buildCloudFormationStackSnapshot(cloudformationSvc, fullStack)
		if err != nil {
			return nil, nil, err
		}

		// Set meta data not known directly by the stack
		cfnStackSnapshot.Region = pollerInput.Region
		cfnStackSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      cfnStackSnapshot,
			ID:              *cfnStackSnapshot.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.CloudFormationStackSchema,
		})
	}

	return resources, marker, nil
}
