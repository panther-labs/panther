package remediation

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
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	remediationmodels "github.com/panther-labs/panther/api/lambda/remediation/models"
	resourcemodels "github.com/panther-labs/panther/api/lambda/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const remediationAction = "remediate"
const listRemediationsAction = "listRemediations"

var (
	remediationLambdaArn = os.Getenv("REMEDIATION_LAMBDA_ARN")

	awsSession   = session.Must(session.NewSession())
	lambdaClient = lambda.New(awsSession)

	analysisClient  gatewayapi.API = gatewayapi.NewClient(lambdaClient, "panther-analysis-api")
	resourcesClient gatewayapi.API = gatewayapi.NewClient(lambdaClient, "panther-resources-api")

	ErrNotFound = errors.New("Remediation not associated with policy")
)

// Remediate will invoke remediation action in an AWS account
func (remediator *Invoker) Remediate(remediation *remediationmodels.RemediateResourceInput) error {
	zap.L().Debug("handling remediation",
		zap.Any("policyId", remediation.PolicyID),
		zap.Any("resourceId", remediation.ResourceID))

	policy, err := getPolicy(remediation.PolicyID)
	if err != nil {
		return errors.Wrap(err, "Encountered issue when getting policy")
	}

	if policy.AutoRemediationID == "" {
		return ErrNotFound
	}

	resource, err := getResource(remediation.ResourceID)
	if err != nil {
		return errors.Wrap(err, "Encountered issue when getting resource")
	}
	remediationPayload := &Payload{
		RemediationID: policy.AutoRemediationID,
		Resource:      resource.Attributes,
		Parameters:    policy.AutoRemediationParameters,
	}
	lambdaInput := &LambdaInput{
		Action:  aws.String(remediationAction),
		Payload: remediationPayload,
	}

	_, err = remediator.invokeLambda(lambdaInput)
	if err != nil {
		return errors.Wrap(err, "failed to invoke remediator")
	}

	zap.L().Debug("finished remediate action")
	return nil
}

//GetRemediations invokes the Lambda in customer account and retrieves the list of available remediations
func (remediator *Invoker) GetRemediations() (*remediationmodels.ListRemediationsOutput, error) {
	zap.L().Info("getting list of remediations")

	lambdaInput := &LambdaInput{Action: aws.String(listRemediationsAction)}

	result, err := remediator.invokeLambda(lambdaInput)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("got response from Remediation Lambda",
		zap.String("lambdaResponse", string(result)))

	var remediations remediationmodels.ListRemediationsOutput
	if err := jsoniter.Unmarshal(result, &remediations); err != nil {
		return nil, err
	}

	zap.L().Debug("finished action to get remediations")
	return &remediations, nil
}

func getPolicy(policyID string) (*analysismodels.Policy, error) {
	input := analysismodels.LambdaInput{
		GetPolicy: &analysismodels.GetPolicyInput{ID: policyID},
	}
	var policy analysismodels.Policy

	if _, err := analysisClient.Invoke(&input, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

func getResource(resourceID string) (*resourcemodels.Resource, error) {
	input := resourcemodels.LambdaInput{
		GetResource: &resourcemodels.GetResourceInput{ID: resourceID},
	}
	var result resourcemodels.Resource
	if _, err := resourcesClient.Invoke(&input, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (remediator *Invoker) invokeLambda(lambdaInput *LambdaInput) ([]byte, error) {
	serializedPayload, err := jsoniter.Marshal(lambdaInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal lambda input")
	}

	invokeInput := &lambda.InvokeInput{
		Payload:      serializedPayload,
		FunctionName: aws.String(remediationLambdaArn),
	}

	response, err := remediator.lambdaClient.Invoke(invokeInput)
	if err != nil {
		return nil, err
	}

	if response.FunctionError != nil {
		return nil, errors.New("error invoking lambda: " + string(response.Payload))
	}

	zap.L().Debug("finished Lambda invocation")
	return response.Payload, nil
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
