package remediation

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
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	analysisclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	analysisoperations "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	remediationmodels "github.com/panther-labs/panther/api/gateway/remediation/models"
	resourcesclient "github.com/panther-labs/panther/api/gateway/resources/client"
	resourcesoperations "github.com/panther-labs/panther/api/gateway/resources/client/operations"
	resourcesmodels "github.com/panther-labs/panther/api/gateway/resources/models"
	organizationmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const remediationAction = "remediate"
const listRemediationsAction = "listRemediations"

var (
	crossAccountRoleName     = os.Getenv("CROSS_ACCOUNT_ROLE")
	sessionDurationSeconds   = os.Getenv("CROSS_ACCOUNT_SESSION_DURATION")
	organizationsAPI         = os.Getenv("ORGANIZATIONS_API")
	policiesServiceHostname  = os.Getenv("POLICIES_SERVICE_HOSTNAME")
	policiesServicePath      = os.Getenv("POLICIES_SERVICE_PATH")
	resourcesServiceHostname = os.Getenv("RESOURCES_SERVICE_HOSTNAME")
	resourcesServicePath     = os.Getenv("RESOURCES_SERVICE_PATH")

	// Cache of AWS credentials
	cache *aws.Config

	// Creating variables to make possible to mock 3rd party libraries
	getLambda = getLambdaFunc
	getCreds  = stscreds.NewCredentials

	awsSession     = session.Must(session.NewSession())
	httpClient     = gatewayapi.GatewayClient(awsSession)
	policiesConfig = analysisclient.DefaultTransportConfig().
			WithBasePath(policiesServicePath).
			WithHost(policiesServiceHostname)
	policiesClient = analysisclient.NewHTTPClientWithConfig(nil, policiesConfig)

	resourcesConfig = resourcesclient.DefaultTransportConfig().
			WithBasePath(resourcesServicePath).
			WithHost(resourcesServiceHostname)
	resourcesClient = resourcesclient.NewHTTPClientWithConfig(nil, resourcesConfig)
)

// Remediate will invoke remediation action in an AWS account
func (remediator *Invoker) Remediate(remediation *remediationmodels.RemediateResource) error {
	zap.L().Info("handling remediation",
		zap.Any("policyId", remediation.PolicyID),
		zap.Any("resourceId", remediation.ResourceID))

	policy, err := getPolicy(string(remediation.PolicyID))
	if err != nil {
		zap.L().Warn("Encountered issue when getting policy",
			zap.Any("policyId", remediation.PolicyID))
		return err
	}

	if policy.AutoRemediationID == "" {
		zap.L().Info("There is no remediation configured for this policy",
			zap.Any("policyId", remediation.PolicyID))
		return nil
	}

	resource, err := getResource(string(remediation.ResourceID))
	if err != nil {
		zap.L().Warn("Encountered issue when getting resource",
			zap.Any("resourceId", remediation.ResourceID))
		return err
	}
	remediationPayload := &Payload{
		RemediationID: string(policy.AutoRemediationID),
		Resource:      resource.Attributes,
		Parameters:    policy.AutoRemediationParameters,
	}
	lambdaInput := &LambdaInput{
		Action:  aws.String(remediationAction),
		Payload: remediationPayload,
	}

	_, err = remediator.invokeLambda(lambdaInput)
	if err != nil {
		return err
	}

	zap.L().Info("finished remediate action")
	return nil
}

//GetRemediations invokes the Lambda in customer account and retrieves the list of available remediations
func (remediator *Invoker) GetRemediations() (*remediationmodels.Remediations, error) {
	zap.L().Info("getting list of remediations")

	lambdaInput := &LambdaInput{Action: aws.String(listRemediationsAction)}

	result, err := remediator.invokeLambda(lambdaInput)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("got response from Remediation Lambda",
		zap.String("lambdaResponse", string(result)))

	var remediations remediationmodels.Remediations
	if err := jsoniter.Unmarshal(result, &remediations); err != nil {
		return nil, err
	}

	zap.L().Info("finished action to get remediations")
	return &remediations, nil
}

func getPolicy(policyID string) (*analysismodels.Policy, error) {
	policy, err := policiesClient.Operations.GetPolicy(&analysisoperations.GetPolicyParams{
		PolicyID:   policyID,
		HTTPClient: httpClient,
	})

	if err != nil {
		return nil, err
	}
	return policy.Payload, nil
}

func getResource(resourceID string) (*resourcesmodels.Resource, error) {
	resource, err := resourcesClient.Operations.GetResource(&resourcesoperations.GetResourceParams{
		ResourceID: resourceID,
		HTTPClient: httpClient,
	})

	if err != nil {
		return nil, err
	}
	return resource.Payload, nil
}

func (remediator *Invoker) invokeLambda(lambdaInput *LambdaInput) ([]byte, error) {
	customerLambdaFunctionArn, err := remediator.getLambdaArn()
	if err != nil {
		return nil, err
	}

	serializedPayload, err := jsoniter.Marshal(lambdaInput)
	if err != nil {
		return nil, err
	}

	invokeInput := &lambda.InvokeInput{
		Payload:      serializedPayload,
		FunctionName: customerLambdaFunctionArn,
	}

	zap.L().Info("invoking Lambda in customer account")

	creds, err := remediator.getAwsCredentials(*customerLambdaFunctionArn)
	if err != nil {
		return nil, err
	}

	lambdaClient := getLambda(remediator.awsSession, creds)
	var response *lambda.InvokeOutput
	if response, err = lambdaClient.Invoke(invokeInput); err != nil {
		return nil, err
	}

	if response.FunctionError != nil {
		return nil, errors.New("error invoking lambda: " + string(response.Payload))
	}

	zap.L().Info("finished Lambda invocation",
		zap.String("functionArn", *customerLambdaFunctionArn))

	return response.Payload, nil
}

func (remediator *Invoker) getAwsCredentials(functionArn string) (*aws.Config, error) {
	if cache != nil {
		return cache, nil
	}

	parsedArn, err := arn.Parse(functionArn)
	if err != nil {
		return nil, err
	}
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s",
		parsedArn.AccountID,
		crossAccountRoleName)
	zap.L().Info("fetching new credentials from assumed role", zap.String("roleArn", roleArn))

	creds := getCreds(remediator.awsSession, roleArn, func(p *stscreds.AssumeRoleProvider) {
		p.Duration = time.Duration(mustParseInt(sessionDurationSeconds)) * time.Second
	})

	config := &aws.Config{Region: aws.String(parsedArn.Region), Credentials: creds}
	cache = config
	return config, nil
}

func mustParseInt(text string) int {
	val, err := strconv.Atoi(text)
	if err != nil {
		panic(err)
	}
	return val
}

func getLambdaFunc(p client.ConfigProvider, cfgs *aws.Config) lambdaiface.LambdaAPI {
	return lambda.New(p, cfgs)
}

func (remediator *Invoker) getLambdaArn() (*string, error) {
	input := organizationmodels.LambdaInput{GetOrganization: &organizationmodels.GetOrganizationInput{}}
	var output organizationmodels.GetOrganizationOutput
	if err := genericapi.Invoke(remediator.lambdaClient, organizationsAPI, &input, &output); err != nil {
		return nil, err
	}

	if output.Organization.RemediationConfig == nil || output.Organization.RemediationConfig.AwsRemediationLambdaArn == nil {
		return nil, &genericapi.DoesNotExistError{Message: "there is no aws remediation lambda configured for organization"}
	}
	return output.Organization.RemediationConfig.AwsRemediationLambdaArn, nil
}

//LambdaInput is the input to the Remediation Lambda running in customer account
type LambdaInput struct {
	Action  *string     `json:"action"`
	Payload interface{} `json:"payload,omitempty"`
}

// Payload is the input to the Lambda running in customer account
// that will perform the remediation tasks
type Payload struct {
	RemediationID string      `json:"remediationId"`
	Resource      interface{} `json:"resource"`
	Parameters    interface{} `json:"parameters"`
}
