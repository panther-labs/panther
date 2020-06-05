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
	"crypto/sha1" // nolint: gosec
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/magefile/mage/sh"
)

const (
	maxTemplateSize = 51200 // Max file size before CFN templates must be uploaded to S3

	pollInterval = 5 * time.Second // How long to wait in between requests to the CloudFormation service
)

var (
	gitVersion string // set in deployPrecheck()
)

// Deploy a CloudFormation template, returning stack outputs.
//
// The bucket parameter can be empty to skip S3 packaging.
func deployTemplate(
	awsSession *session.Session,
	templatePath, bucket, stack string,
	params map[string]string,
) (map[string]string, error) {

	// 1) Generate final template, with large assets packaged in S3.
	packagedTemplate, err := samPackage(*awsSession.Config.Region, templatePath, bucket)
	if err != nil {
		return nil, err
	}

	// 2) If the stack already exists, wait for it to reach a steady state.
	outputs, err := prepareStack(awsSession, stack)
	if err != nil {
		return nil, err
	}

	// 3) Create a change set
	changeSetType := "CREATE"
	if outputs != nil {
		// We have outputs, so the stack must already exist
		changeSetType = "UPDATE"
	}

	changeID, err := createChangeSet(awsSession, bucket, stack, changeSetType, packagedTemplate, params)
	if err != nil {
		return nil, err
	}
	if changeID == nil {
		// No changes - return the outputs we already had
		return outputs, nil
	}

	// 4) Execute the change set
	return executeChangeSet(awsSession, changeID, changeSetType, stack)
}

// Package resources in S3 and return the path to the modified CloudFormation template.
//
// This uses "sam package" to be compatible with SAR, which is also more complete and robust than
// "aws cloudformation package"
//
// The bucket name can be blank if no S3 bucket is actually needed (e.g. bootstrap stack).
func samPackage(region, templatePath, bucket string) (string, error) {
	logger.Debugf("deploy: packaging %s assets", templatePath)
	if bucket == "" {
		// "sam package" requires a bucket name even if it isn't used
		// Put a default value that can't be possibly be a real bucket (names must have 3+ characters)
		bucket = "NA"
	}

	outFile := filepath.Join("out", "deployments", "package."+filepath.Base(templatePath))
	if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
		return "", fmt.Errorf("failed to create out/deployments: %v", err)
	}

	return outFile, sh.Run(filepath.Join(pythonVirtualEnvPath, "bin", "sam"),
		"package", "--s3-bucket", bucket, "-t", templatePath, "--output-template-file", outFile, "--region", region)
}

// Upload a CloudFormation asset to S3 if it doesn't already exist, returning s3 object key and version
func uploadAsset(awsSession *session.Session, assetPath, bucket, stack string) (string, string, error) {
	contents, err := ioutil.ReadFile(assetPath)
	if err != nil {
		return "", "", fmt.Errorf("package %s: failed to open %s: %v", stack, assetPath, err)
	}

	// We are using SHA1 for caching / asset lookup, we don't need strong cryptographic guarantees
	hash := sha1.Sum(contents) // nolint: gosec
	s3Key := fmt.Sprintf("%s/%x", stack, hash)
	client := s3.New(awsSession)
	response, err := client.HeadObject(&s3.HeadObjectInput{Bucket: &bucket, Key: &s3Key})
	if err == nil {
		return s3Key, *response.VersionId, nil // object already exists in S3 with the same hash
	}

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NotFound" {
		// object does not exist yet - upload it!
		response, err := uploadFileToS3(awsSession, assetPath, bucket, s3Key)
		if err != nil {
			return "", "", fmt.Errorf("package %s: failed to upload %s: %v", stack, assetPath, err)
		}
		return s3Key, *response.VersionID, nil
	}

	// Some other error related to HeadObject
	return "", "", fmt.Errorf("package %s: failed to describe s3://%s/%s: %v", stack, bucket, s3Key, err)
}

// Before a change set can be created, the stack needs to be in a steady state.
//
// If the stack is ROLLBACK_COMPLETE or otherwise failed to create, it will be deleted automatically.
// If the stack is still in progress, this will wait until it finishes.
// If the stack exists, its outputs are returned to the caller (once complete).
//     A return of (nil, nil) means the stack does not exist.
func prepareStack(awsSession *session.Session, stackName string) (map[string]string, error) {
	client := cfn.New(awsSession)

	// Wait for the stack to reach a terminal state
	stack, err := waitForStack(client, stackName, "")
	if err != nil {
		return nil, err
	}

	status := *stack.StackStatus
	switch status {
	case cfn.StackStatusDeleteComplete:
		return nil, nil

	case cfn.StackStatusUpdateRollbackFailed:
		return nil, fmt.Errorf(
			"stack %s is %s: you must manually continue rollback or delete the stack", stackName, status)

	case cfn.StackStatusCreateFailed, cfn.StackStatusDeleteFailed, cfn.StackStatusReviewInProgress,
		cfn.StackStatusRollbackComplete, cfn.StackStatusRollbackFailed:
		// A stack in one of these states must be deleted before we can apply new change sets.
		// These are caused by a failed stack creation or deletion; in either case CFN already has
		// tried destroying existing resources or is about to. (This is *not* a failed update.)
		// Deleted stacks are retained and viewable in the AWS CloudFormation console for 90 days.

		if stackName == bootstrapStack {
			// If the very first stack failed to create, we need to do a full teardown before trying again.
			// Otherwise, there may be orphaned S3 buckets that will never be used.
			logger.Warnf("The very first %s stack never created successfully (%s)", bootstrapStack, status)
			logger.Warnf("Running 'mage teardown' to fully remove orphaned resources before trying again")
			Teardown()
			return nil, nil
		}

		logger.Warnf("deleting stack %s (%s) before it can be re-deployed", stackName, status)
		if _, err := client.DeleteStack(&cfn.DeleteStackInput{StackName: &stackName}); err != nil {
			return nil, fmt.Errorf("failed to start stack %s deletion: %v", stackName, err)
		}
		_, err = waitForStackDelete(client, stackName)
		return nil, err // stack deleted - there are no outputs

	default:
		return flattenStackOutputs(stack), nil
	}
}

// Create a CloudFormation change set, returning its id.
//
// If there are no changes, the change set is deleted and (nil, nil) is returned.
func createChangeSet(
	awsSession *session.Session,
	bucket, stack string,
	changeSetType string, // "CREATE" or "UPDATE"
	templatePath string,
	params map[string]string,
) (*string, error) {

	parameters := make([]*cfn.Parameter, 0, len(params))
	for key, val := range params {
		parameters = append(parameters, &cfn.Parameter{
			ParameterKey:   aws.String(key),
			ParameterValue: aws.String(val),
		})
	}

	// add version tag to all objects ("untagged" if not set)
	pantherVersion := gitVersion
	if pantherVersion == "" {
		pantherVersion = "untagged"
	}

	createInput := &cfn.CreateChangeSetInput{
		Capabilities: []*string{
			aws.String("CAPABILITY_AUTO_EXPAND"),
			aws.String("CAPABILITY_IAM"),
			aws.String("CAPABILITY_NAMED_IAM"),
		},
		ChangeSetName: aws.String(fmt.Sprintf("panther-%d", time.Now().UnixNano())),
		ChangeSetType: &changeSetType,
		Parameters:    parameters,
		StackName:     &stack,
		Tags: []*cfn.Tag{ // Tags are propagated to every supported resource in the stack
			{Key: aws.String("Application"), Value: aws.String("Panther")},
			{Key: aws.String("PantherEdition"), Value: aws.String("Community")},
			{Key: aws.String("PantherVersion"), Value: &pantherVersion},
			{Key: aws.String("Stack"), Value: &stack},
		},
	}

	template, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template %s: %v", templatePath, err)
	}

	if len(template) <= maxTemplateSize {
		createInput.SetTemplateBody(string(template))
	} else {
		// Upload to S3 (if it doesn't already exist)
		key, _, err := uploadAsset(awsSession, templatePath, bucket, stack)
		if err != nil {
			return nil, err
		}
		createInput.SetTemplateURL(fmt.Sprintf("https://s3.amazonaws.com/%s/%s", bucket, key))
	}

	logger.Infof("deploy: %s CloudFormation stack %s", strings.ToLower(changeSetType), stack)
	client := cfn.New(awsSession)
	if _, err := client.CreateChangeSet(createInput); err != nil {
		return nil, fmt.Errorf("failed to create change set for stack %s: %v", stack, err)
	}

	return waitForChangeSet(client, *createInput.ChangeSetName, stack)
}

// Wait for the change set to finish creating.
//
// Returns the change set ID, or nil if it was deleted (indicating no changes).
// Returns an error if the final status is not CREATE_COMPLETE.
func waitForChangeSet(client *cfn.CloudFormation, changeSetName, stack string) (*string, error) {
	input := &cfn.DescribeChangeSetInput{ChangeSetName: &changeSetName, StackName: &stack}
	for {
		response, err := client.DescribeChangeSet(input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe change set %s for stack %s: %v", changeSetName, stack, err)
		}

		switch *response.Status {
		case cfn.ChangeSetStatusCreateComplete:
			return &changeSetName, nil // Done! Changes applied
		case cfn.ChangeSetStatusCreatePending, cfn.ChangeSetStatusCreateInProgress:
			time.Sleep(pollInterval)
		case cfn.ChangeSetStatusDeleteComplete, cfn.ChangeSetStatusFailed:
			reason := aws.StringValue(response.StatusReason)

			if strings.HasPrefix(reason, "The submitted information didn't contain changes") ||
				strings.HasPrefix(reason, "No updates are to be performed") {

				// no changes needed - delete the change set
				logger.Debugf("deploy: stack %s is already up to date", stack)
				_, err := client.DeleteChangeSet(&cfn.DeleteChangeSetInput{ChangeSetName: &changeSetName, StackName: &stack})
				if err != nil {
					logger.Warnf("failed to delete change set %s for stack %s: %v", changeSetName, stack, err)
				}

				return nil, nil
			}

			// Change set failed, but not because the stack was already up to date.
			return nil, fmt.Errorf("stack %s change set is %s: %s", stack, *response.Status, reason)
		}
	}
}

// Execute a change set, blocking until the stack has finished updating and then returning its outputs.
func executeChangeSet(awsSession *session.Session, changeSet *string, changeSetType string, stackName string) (map[string]string, error) {
	client := cfn.New(awsSession)
	_, err := client.ExecuteChangeSet(&cfn.ExecuteChangeSetInput{ChangeSetName: changeSet, StackName: &stackName})
	if err != nil {
		return nil, fmt.Errorf("failed to execute change set for stack %s: %v", stackName, err)
	}

	// Wait for change set to finish.
	var stack *cfn.Stack
	if changeSetType == "CREATE" {
		stack, err = waitForStackCreate(client, stackName)
	} else {
		stack, err = waitForStackUpdate(client, stackName)
	}
	if err != nil {
		return nil, err
	}

	return flattenStackOutputs(stack), nil
}
