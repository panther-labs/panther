package aws

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	LambdaClientFunc = setupLambdaClient
)

func setupLambdaClient(sess *session.Session, cfg *aws.Config) interface{} {
	return lambda.New(sess, cfg)
}

func getLambdaClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (lambdaiface.LambdaAPI, error) {
	client, err := getClient(pollerResourceInput, LambdaClientFunc, "lambda", region)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	return client.(lambdaiface.LambdaAPI), nil
}

// PollLambdaFunction polls a single Lambda Function resource
func PollLambdaFunction(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	lambdaClient, err := getLambdaClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	lambdaFunction := getLambda(lambdaClient, scanRequest.ResourceID)

	snapshot := buildLambdaFunctionSnapshot(lambdaClient, lambdaFunction)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	return snapshot, nil
}

// getLambda returns a specific Lambda function configuration
func getLambda(svc lambdaiface.LambdaAPI, functionARN *string) *lambda.FunctionConfiguration {
	functions := listFunctions(svc)
	if len(functions) == 0 {
		return nil
	}
	for _, function := range functions {
		if *function.FunctionArn == *functionARN {
			return function
		}
	}

	zap.L().Warn("tried to scan non-existent resource",
		zap.String("resource", *functionARN),
		zap.String("resourceType", awsmodels.LambdaFunctionSchema))
	return nil
}

// listFunctions returns all lambda functions in the account
func listFunctions(lambdaSvc lambdaiface.LambdaAPI) (functions []*lambda.FunctionConfiguration) {
	err := lambdaSvc.ListFunctionsPages(&lambda.ListFunctionsInput{},
		func(page *lambda.ListFunctionsOutput, lastPage bool) bool {
			functions = append(functions, page.Functions...)
			return true
		})
	if err != nil {
		utils.LogAWSError("Lambda.ListFunctionsPages", err)
	}
	return
}

// listTags returns the tags for a given lambda function
func listTagsLambda(lambdaSvc lambdaiface.LambdaAPI, arn *string) (map[string]*string, error) {
	out, err := lambdaSvc.ListTags(&lambda.ListTagsInput{Resource: arn})
	if err != nil {
		utils.LogAWSError("Lambda.ListTags", err)
		return nil, err
	}

	return out.Tags, nil
}

// getPolicy returns the IAM policy attached to the lambda function, if one exists
func getPolicy(lambdaSvc lambdaiface.LambdaAPI, name *string) (*lambda.GetPolicyOutput, error) {
	out, err := lambdaSvc.GetPolicy(&lambda.GetPolicyInput{FunctionName: name})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "ResourceNotFoundException" {
				zap.L().Debug("No Lambda Policy set", zap.String("function name", *name))
				return nil, err
			}
		}
		utils.LogAWSError("Lambda.GetFunction", err)
		return nil, err
	}

	return out, nil
}

// buildLambdaFunctionSnapshot returns a complete snapshot of a Lambda function
func buildLambdaFunctionSnapshot(
	lambdaSvc lambdaiface.LambdaAPI,
	configuration *lambda.FunctionConfiguration,
) *awsmodels.LambdaFunction {

	if configuration == nil {
		return nil
	}
	lambdaFunction := &awsmodels.LambdaFunction{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   configuration.FunctionArn,
			ResourceType: aws.String(awsmodels.LambdaFunctionSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  configuration.FunctionArn,
			Name: configuration.FunctionName,
		},
		CodeSha256:       configuration.CodeSha256,
		CodeSize:         configuration.CodeSize,
		DeadLetterConfig: configuration.DeadLetterConfig,
		Description:      configuration.Description,
		Environment:      configuration.Environment,
		Handler:          configuration.Handler,
		KMSKeyArn:        configuration.KMSKeyArn,
		LastModified:     configuration.LastModified,
		Layers:           configuration.Layers,
		MasterArn:        configuration.MasterArn,
		MemorySize:       configuration.MemorySize,
		RevisionId:       configuration.RevisionId,
		Role:             configuration.Role,
		Runtime:          configuration.Runtime,
		Timeout:          configuration.Timeout,
		TracingConfig:    configuration.TracingConfig,
		Version:          configuration.Version,
		VpcConfig:        configuration.VpcConfig,
	}

	tags, err := listTagsLambda(lambdaSvc, configuration.FunctionArn)
	if err == nil {
		lambdaFunction.Tags = tags
	}

	policy, err := getPolicy(lambdaSvc, configuration.FunctionName)
	if err == nil {
		lambdaFunction.Policy = policy
	}

	return lambdaFunction
}

// PollLambdaFunctions gathers information on each Lambda Function for an AWS account.
func PollLambdaFunctions(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting Lambda Function resource poller")
	lambdaFunctionSnapshots := make(map[string]*awsmodels.LambdaFunction)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "lambda") {
		lambdaSvc, err := getLambdaClient(pollerInput, *regionID)
		if err != nil {
			return nil, err // error is logged in getClient()
		}

		// Start with generating a list of all functions
		functions := listFunctions(lambdaSvc)
		if len(functions) == 0 {
			zap.L().Debug("no Lambda functions found", zap.String("region", *regionID))
			continue
		}

		for _, functionConfiguration := range functions {
			lambdaFunctionSnapshot := buildLambdaFunctionSnapshot(lambdaSvc, functionConfiguration)
			if lambdaFunctionSnapshot == nil {
				continue
			}
			lambdaFunctionSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			lambdaFunctionSnapshot.Region = regionID

			if _, ok := lambdaFunctionSnapshots[*lambdaFunctionSnapshot.ARN]; !ok {
				lambdaFunctionSnapshots[*lambdaFunctionSnapshot.ARN] = lambdaFunctionSnapshot
			} else {
				zap.L().Info(
					"overwriting existing Lambda Function snapshot",
					zap.String("resourceId", *lambdaFunctionSnapshot.ARN),
				)
				lambdaFunctionSnapshots[*lambdaFunctionSnapshot.ARN] = lambdaFunctionSnapshot
			}
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(lambdaFunctionSnapshots))
	for resourceID, lambdaSnapshot := range lambdaFunctionSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      lambdaSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.LambdaFunctionSchema,
		})
	}

	return resources, nil
}
