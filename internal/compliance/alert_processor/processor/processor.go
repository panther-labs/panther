package processor

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
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	analysisclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	analysisoperations "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	alertmodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	remediationmodels "github.com/panther-labs/panther/api/lambda/remediation/models"
	"github.com/panther-labs/panther/internal/compliance/alert_processor/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const alertSuppressPeriod = 3600 // 1 hour

var (
	policyServiceHost = os.Getenv("POLICY_SERVICE_HOST")
	policyServicePath = os.Getenv("POLICY_SERVICE_PATH")

	ddbTable = os.Getenv("TABLE_NAME")

	awsSession                             = session.Must(session.NewSession())
	ddbClient    dynamodbiface.DynamoDBAPI = dynamodb.New(awsSession)
	lambdaClient lambdaiface.LambdaAPI     = lambda.New(awsSession)
	httpClient                             = gatewayapi.GatewayClient(awsSession)

	complianceClient  gatewayapi.API = gatewayapi.NewClient(lambdaClient, "panther-compliance-api")
	remediationClient gatewayapi.API = gatewayapi.NewClient(lambdaClient, "panther-remediation-api")

	policyConfig = analysisclient.DefaultTransportConfig().
			WithHost(policyServiceHost).
			WithBasePath(policyServicePath)
	policyClient = analysisclient.NewHTTPClientWithConfig(nil, policyConfig)
)

//Handle method checks if a resource is compliant for a rule or not.
// If the resource is compliant, it will do nothing
// If the resource is not compliant, it will trigger an auto-remediation action
// and an alert - if alerting is not suppressed
func Handle(event *models.ComplianceNotification) error {
	zap.L().Debug("received new event", zap.String("resourceId", event.ResourceID))

	triggerActions, err := shouldTriggerActions(event)
	if err != nil {
		return err
	}
	if !triggerActions {
		zap.L().Debug("no action needed for resources", zap.String("resourceId", event.ResourceID))
		return nil
	}

	canRemediate, err := triggerAlert(event)
	if err != nil {
		return err
	}

	if canRemediate {
		if err := triggerRemediation(event); err != nil {
			return err
		}
	}

	zap.L().Debug("finished processing event", zap.String("resourceId", event.ResourceID))
	return nil
}

// We should trigger actions on resource if the resource is failing for a policy
func shouldTriggerActions(event *models.ComplianceNotification) (bool, error) {
	zap.L().Debug("getting resource status",
		zap.String("policyId", event.PolicyID),
		zap.String("resourceId", event.ResourceID))

	input := &compliancemodels.LambdaInput{
		GetStatus: &compliancemodels.GetStatusInput{
			PolicyID:   event.PolicyID,
			ResourceID: event.ResourceID,
		},
	}
	var response compliancemodels.ComplianceEntry
	statusCode, err := complianceClient.Invoke(input, &response)
	if err != nil {
		if statusCode == http.StatusNotFound {
			return false, nil
		}
		return false, errors.Wrapf(err, "failed to get compliance status for policyID %s and resource %s",
			event.PolicyID, event.ResourceID)
	}

	zap.L().Debug("got resource status",
		zap.String("policyId", event.PolicyID),
		zap.String("resourceId", event.ResourceID),
		zap.String("status", string(response.Status)))

	return response.Status == compliancemodels.StatusFail, nil
}

func triggerAlert(event *models.ComplianceNotification) (canRemediate bool, err error) {
	if !event.ShouldAlert {
		zap.L().Debug("skipping alert notification", zap.String("policyId", event.PolicyID))
		return false, nil
	}
	timeNow := time.Now().Unix()
	expiresAt := int64(alertSuppressPeriod) + timeNow

	var alertConfig *alertmodel.Alert
	alertConfig, canRemediate, err = getAlertConfigPolicy(event)
	if err != nil {
		return false, errors.Wrapf(err, "encountered issue when getting policy: %s", event.PolicyID)
	}

	marshalledAlertConfig, err := jsoniter.Marshal(alertConfig)
	if err != nil {
		return false, errors.Wrapf(err, "failed to marshal alerting config for policy %s", event.PolicyID)
	}

	updateExpression := expression.
		Set(expression.Name("lastUpdated"), expression.Value(aws.Int64(timeNow))).
		Set(expression.Name("alertConfig"), expression.Value(marshalledAlertConfig)).
		Set(expression.Name("expiresAt"), expression.Value(expiresAt))

	// The Condition will succeed only if `alertSuppressPeriod` has passed since the time the previous
	// alert was triggered
	conditionExpression := expression.Name("lastUpdated").LessThan(expression.Value(timeNow - int64(alertSuppressPeriod))).
		Or(expression.Name("lastUpdated").AttributeNotExists())

	combinedExpression, err := expression.NewBuilder().
		WithUpdate(updateExpression).
		WithCondition(conditionExpression).
		Build()
	if err != nil {
		return false, errors.Wrapf(err, "could not build ddb expression for policy: %s", event.PolicyID)
	}

	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(ddbTable),
		Key: map[string]*dynamodb.AttributeValue{
			"policyId": {S: &event.PolicyID},
		},
		UpdateExpression:          combinedExpression.Update(),
		ConditionExpression:       combinedExpression.Condition(),
		ExpressionAttributeNames:  combinedExpression.Names(),
		ExpressionAttributeValues: combinedExpression.Values(),
	}

	zap.L().Debug("updating recent alerts table", zap.String("policyId", event.PolicyID))
	_, err = ddbClient.UpdateItem(input)
	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			zap.L().Debug("update on ddb failed on condition, we will not trigger an alert")
			return canRemediate, nil
		}
		return false, errors.Wrapf(err, "experienced issue while updating ddb table for policy: %s", event.PolicyID)
	}
	return canRemediate, nil
}

func triggerRemediation(event *models.ComplianceNotification) error {
	zap.L().Debug("Triggering auto-remediation",
		zap.String("policyId", event.PolicyID),
		zap.String("resourceId", event.ResourceID),
	)

	input := remediationmodels.LambdaInput{
		RemediateResourceAsync: &remediationmodels.RemediateResourceAsyncInput{
			PolicyID:   event.PolicyID,
			ResourceID: event.ResourceID,
		},
	}
	if _, err := remediationClient.Invoke(&input, nil); err != nil {
		return errors.Wrapf(err, "failed to trigger remediation on policy %s for resource %s",
			event.PolicyID, event.ResourceID)
	}

	zap.L().Debug("successfully triggered auto-remediation action")
	return nil
}

func getAlertConfigPolicy(event *models.ComplianceNotification) (*alertmodel.Alert, bool, error) {
	policy, err := policyClient.Operations.GetPolicy(&analysisoperations.GetPolicyParams{
		PolicyID:   event.PolicyID,
		HTTPClient: httpClient,
	})

	if err != nil {
		return nil, false, errors.Wrapf(err, "encountered issue when getting policy: %s", event.PolicyID)
	}

	return &alertmodel.Alert{
			AnalysisDescription: aws.String(string(policy.Payload.Description)),
			AnalysisID:          event.PolicyID,
			AnalysisName:        aws.String(string(policy.Payload.DisplayName)),
			CreatedAt:           event.Timestamp,
			OutputIds:           event.OutputIds,
			Runbook:             aws.String(string(policy.Payload.Runbook)),
			Severity:            string(policy.Payload.Severity),
			Tags:                policy.Payload.Tags,
			Type:                alertmodel.PolicyType,
			Version:             &event.PolicyVersionID,
		},
		policy.Payload.AutoRemediationID != "", // means we can remediate
		nil
}
