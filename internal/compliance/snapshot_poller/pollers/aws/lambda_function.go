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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
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
		return nil, err
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

	lambdaFunction, err := getLambda(lambdaClient, scanRequest.ResourceID)
	if err != nil || lambdaFunction == nil {
		return nil, err
	}

	snapshot, err := buildLambdaFunctionSnapshot(lambdaClient, lambdaFunction)
	if err != nil {
		return nil, err
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	return snapshot, nil
}

// getLambda returns a specific Lambda function configuration
func getLambda(svc lambdaiface.LambdaAPI, functionARN *string) (*lambda.FunctionConfiguration, error) {
	// The GetFunction API call includes a pre-signed URL pointing to the function's source code, in
	// addition to the rest of the function configuration information.
	// Because of this, the lambda:GetFunction permission is not included in the default IAM audit
	// role permissions managed by AWS. To work around this, we call lambda:ListFunctions (which
	// returns the same information but without the code location and tags) and look for the
	// specific function we need. We could skip this by calling GetFunction, but then we would have
	// to have customers update all the panther audit role permissions or lambda scanning would break
	var functionConfig *lambda.FunctionConfiguration
	err := svc.ListFunctionsPages(&lambda.ListFunctionsInput{},
		func(page *lambda.ListFunctionsOutput, lastPage bool) bool {
			for _, function := range page.Functions {
				if *function.FunctionArn == *functionARN {
					functionConfig = function
					return false
				}
			}
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "Lambda.ListFunctionsPages: %s", aws.StringValue(functionARN))
	}
	if functionConfig == nil {
		zap.L().Warn("tried to scan non-existent resource",
			zap.String("resource", *functionARN),
			zap.String("resourceType", awsmodels.LambdaFunctionSchema))
	}
	return functionConfig, nil
}

// listFunctions returns all lambda functions in the account
func listFunctions(lambdaSvc lambdaiface.LambdaAPI, nextMarker *string) (
	functions []*lambda.FunctionConfiguration, marker *string, err error) {

	err = lambdaSvc.ListFunctionsPages(&lambda.ListFunctionsInput{
		Marker:   nextMarker,
		MaxItems: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *lambda.ListFunctionsOutput, lastPage bool) bool {
			return functionIterator(page, &functions, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "Lambda.ListFunctionsPages")
	}
	return
}

func functionIterator(page *lambda.ListFunctionsOutput, functions *[]*lambda.FunctionConfiguration, marker **string) bool {
	*functions = append(*functions, page.Functions...)
	*marker = page.NextMarker
	return len(*functions) < defaultBatchSize
}

// listTags returns the tags for a given lambda function
func listTagsLambda(lambdaSvc lambdaiface.LambdaAPI, arn *string) (map[string]*string, error) {
	out, err := lambdaSvc.ListTags(&lambda.ListTagsInput{Resource: arn})
	if err != nil {
		return nil, errors.Wrapf(err, "Lambda.ListTags: %s", aws.StringValue(arn))
	}

	return out.Tags, nil
}

// getPolicy returns the IAM policy attached to the lambda function, if one exists
func getPolicy(lambdaSvc lambdaiface.LambdaAPI, name *string) (*lambda.GetPolicyOutput, error) {
	out, err := lambdaSvc.GetPolicy(&lambda.GetPolicyInput{FunctionName: name})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == lambda.ErrCodeResourceNotFoundException {
			zap.L().Debug("No Lambda Policy set", zap.String("function name", *name))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "Lambda.GetFunction: %s", aws.StringValue(name))
	}

	return out, nil
}

// buildLambdaFunctionSnapshot returns a complete snapshot of a Lambda function
func buildLambdaFunctionSnapshot(
	lambdaSvc lambdaiface.LambdaAPI,
	configuration *lambda.FunctionConfiguration,
) (*awsmodels.LambdaFunction, error) {

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
	if err != nil {
		return nil, err
	}
	lambdaFunction.Tags = tags

	policy, err := getPolicy(lambdaSvc, configuration.FunctionName)
	if err != nil {
		return nil, err
	}
	lambdaFunction.Policy = policy

	return lambdaFunction, nil
}

// PollLambdaFunctions gathers information on each Lambda Function for an AWS account.
func PollLambdaFunctions(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting Lambda Function resource poller")

	lambdaSvc, err := getLambdaClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all functions
	functions, marker, err := listFunctions(lambdaSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(functions))
	for _, functionConfiguration := range functions {
		lambdaFunctionSnapshot, err := buildLambdaFunctionSnapshot(lambdaSvc, functionConfiguration)
		if err != nil {
			return nil, nil, err
		}
		lambdaFunctionSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		lambdaFunctionSnapshot.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      lambdaFunctionSnapshot,
			ID:              *lambdaFunctionSnapshot.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.LambdaFunctionSchema,
		})
	}

	return resources, marker, nil
}
