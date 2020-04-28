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
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/s3"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/cfnparse"
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
	template, err := cfnPackage(awsSession, templatePath, bucket, stack)
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

	changeID, err := createChangeSet(awsSession, bucket, stack, changeSetType, template, params)
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

// Upload resources to S3 and return the modified CloudFormation template.
//
// This is similar to the "aws cloudformation package" CLI command, but our implementation
// is more robust and performant. Differences include:
//
//    - We include S3 versions when possible so CFN can quickly check if an asset is identical
//    - We generate zipfiles with hashes that do not depend on timestamps
//    - AWS CLI suffers from a region bug when writing S3 URLs
//        (possibly related to https://github.com/aws/aws-cli/issues/4372)
//
// Resources currently supported:
//    - AWS::AppSync::GraphQLSchema - DefinitionS3Location
//    - AWS::CloudFormation::Stack - TemplateURL
//    - AWS::Serverless::Function - CodeUri
//
// The bucket parameter can be "" to skip S3 packaging (e.g. for the bootstrap stack) -
// in that case, we still parse the template and re-emit it to strip comments / extra spaces
func cfnPackage(awsSession *session.Session, templatePath, bucket, stack string) ([]byte, error) {
	cfnBody, err := cfnparse.ParseTemplate(templatePath)
	if err != nil {
		return nil, err
	}

	if bucket == "" {
		// No S3 packaging - just emit the template in standard form
		return yaml.Marshal(cfnBody)
	}

	logger.Debugf("deploy: packaging %s assets", templatePath)
	for _, resource := range cfnBody["Resources"].(map[string]interface{}) {
		r := resource.(map[string]interface{})
		switch r["Type"].(string) {
		// Note: filepaths are relative to the template, but mage is running from the repo root

		case "AWS::AppSync::GraphQLSchema":
			properties := r["Properties"].(map[string]interface{})
			if path, ok := properties["DefinitionS3Location"].(string); ok && !strings.HasPrefix(path, "s3://") {
				// This GraphQLSchema resource has a file location specified instead of S3 - upload it
				assetPath := filepath.Join(filepath.Dir(templatePath), path)
				key, _, err := uploadAsset(awsSession, assetPath, bucket, stack)
				if err != nil {
					return nil, err
				}
				properties["DefinitionS3Location"] = fmt.Sprintf("s3://%s/%s", bucket, key)
			}

		case "AWS::CloudFormation::Stack":
			properties := r["Properties"].(map[string]interface{})
			if path, ok := properties["TemplateURL"].(string); ok && !strings.HasPrefix(path, "https://") {
				// This TemplateURL resource has a file location instead of S3 - package it

				// Recursively package nested template assets
				nestedTemplatePath := filepath.Join(filepath.Dir(templatePath), path)
				body, err := cfnPackage(awsSession, nestedTemplatePath, bucket, stack)
				if err != nil {
					return nil, err
				}

				// Save the final nested template locally and upload to S3
				savePath := filepath.Join("out", "deployments",
					fmt.Sprintf("%s-nested-%s.yml", stack, filepath.Base(path)))
				if err = writeFile(savePath, body); err != nil {
					return nil, err
				}

				key, _, err := uploadAsset(awsSession, savePath, bucket, stack)
				if err != nil {
					return nil, err
				}
				properties["TemplateURL"] = fmt.Sprintf("https://s3.amazonaws.com/%s/%s", bucket, key)
			}

		case "AWS::Serverless::Function":
			properties := r["Properties"].(map[string]interface{})
			if path, ok := properties["CodeUri"].(string); ok && !strings.HasPrefix(path, "s3://") {
				// This CodeUri resource has a file location specified instead of S3 - upload it
				assetPath := filepath.Join(filepath.Dir(templatePath), path)

				zipPath := filepath.Join("out", "deployments", "zip", properties["FunctionName"].(string)+".zip")
				if err = shutil.ZipDirectory(assetPath, zipPath, false); err != nil {
					return nil, fmt.Errorf("failed to zip %s: %v", assetPath, err)
				}

				key, version, err := uploadAsset(awsSession, zipPath, bucket, stack)
				if err != nil {
					return nil, err
				}
				properties["CodeUri"] = map[string]interface{}{
					"Bucket":  bucket,
					"Key":     key,
					"Version": version,
				}
			}
		}
	}

	return yaml.Marshal(cfnBody)
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
		response, err := uploadFileToS3(awsSession, assetPath, bucket, s3Key, nil)
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
			// Otherwise, there may be orphaned S3 buckets and an ACM cert that will never be used.
			logger.Warnf("The very first %s stack never created successfully (%s)", bootstrapStack, status)
			logger.Warnf("Running 'mage teardown' to fully remove orphaned resources before trying again")
			Teardown()
			return nil, nil
		}

		logger.Warnf("deleting stack %s (%s) before it can be re-deployed", stackName, status)
		if _, err := client.DeleteStack(&cfn.DeleteStackInput{StackName: &stackName}); err != nil {
			return nil, fmt.Errorf("failed to start stack %s deletion: %v", stackName, err)
		}
		if _, err := waitForStackDelete(client, stackName); err != nil {
			return nil, err
		}
	}

	return flattenStackOutputs(stack), nil
}

// Create a CloudFormation change set, returning its id.
//
// If there are no changes, the change set is deleted and (nil, nil) is returned.
func createChangeSet(
	awsSession *session.Session,
	bucket, stack string,
	changeSetType string, // "CREATE" or "UPDATE"
	template []byte,
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
			{Key: aws.String("PantherVersion"), Value: &pantherVersion},
			{Key: aws.String("Stack"), Value: &stack},
		},
	}

	// Always save the final template to help with troubleshooting a failed deployment.
	path := filepath.Join("out", "deployments", stack+".yml")
	if err := writeFile(path, template); err != nil {
		return nil, err
	}

	if len(template) <= maxTemplateSize {
		createInput.SetTemplateBody(string(template))
	} else {
		// Upload to S3 (if it doesn't already exist)
		key, _, err := uploadAsset(awsSession, path, bucket, stack)
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
