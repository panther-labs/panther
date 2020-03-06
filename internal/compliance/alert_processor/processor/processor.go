package processor

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
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	analysisclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	analysisoperations "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	complianceclient "github.com/panther-labs/panther/api/gateway/compliance/client"
	complianceoperations "github.com/panther-labs/panther/api/gateway/compliance/client/operations"
	compliancemodels "github.com/panther-labs/panther/api/gateway/compliance/models"
	remediationclient "github.com/panther-labs/panther/api/gateway/remediation/client"
	remediationoperations "github.com/panther-labs/panther/api/gateway/remediation/client/operations"
	remediationmodels "github.com/panther-labs/panther/api/gateway/remediation/models"
	"github.com/panther-labs/panther/internal/compliance/alert_processor/models"
	alertmodel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const alertSuppressPeriod = 3600 // 1 hour

var (
	remediationServiceHost = os.Getenv("REMEDIATION_SERVICE_HOST")
	remediationServicePath = os.Getenv("REMEDIATION_SERVICE_PATH")
	complianceServiceHost  = os.Getenv("COMPLIANCE_SERVICE_HOST")
	complianceServicePath  = os.Getenv("COMPLIANCE_SERVICE_PATH")
	policyServiceHost      = os.Getenv("POLICY_SERVICE_HOST")
	policyServicePath      = os.Getenv("POLICY_SERVICE_PATH")

	ddbTable = os.Getenv("TABLE_NAME")

	awsSession                           = session.Must(session.NewSession())
	ddbClient  dynamodbiface.DynamoDBAPI = dynamodb.New(awsSession)
	httpClient                           = gatewayapi.GatewayClient(awsSession)

	remediationconfig = remediationclient.DefaultTransportConfig().
				WithHost(remediationServiceHost).
				WithBasePath(remediationServicePath)
	remediationClient = remediationclient.NewHTTPClientWithConfig(nil, remediationconfig)

	complianceConfig = complianceclient.DefaultTransportConfig().
				WithHost(complianceServiceHost).
				WithBasePath(complianceServicePath)
	complianceClient = complianceclient.NewHTTPClientWithConfig(nil, complianceConfig)

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
	zap.L().Info("received new event",
		zap.String("resourceId", *event.ResourceID))

	triggerActions, err := shouldTriggerActions(event)
	if err != nil {
		return err
	}
	if !triggerActions {
		zap.L().Info("no action needed for resources",
			zap.String("resourceId", *event.ResourceID))
		return nil
	}

	if err := triggerAlert(event); err != nil {
		return err
	}

	if err := triggerRemediation(event); err != nil {
		return err
	}

	zap.L().Info("finished processing event",
		zap.String("resourceId", *event.ResourceID))
	return nil
}

// We should trigger actions on resource if the resource is failing for a policy
func shouldTriggerActions(event *models.ComplianceNotification) (bool, error) {
	zap.L().Info("getting resource status",
		zap.String("policyId", *event.PolicyID),
		zap.String("resourceId", *event.ResourceID))
	response, err := complianceClient.Operations.GetStatus(
		&complianceoperations.GetStatusParams{
			PolicyID:   *event.PolicyID,
			ResourceID: *event.ResourceID,
			HTTPClient: httpClient,
		})

	if err != nil {
		return false, err
	}

	zap.L().Info("got resource status",
		zap.String("policyId", *event.PolicyID),
		zap.String("resourceId", *event.ResourceID),
		zap.String("status", string(response.Payload.Status)))

	return response.Payload.Status == compliancemodels.StatusFAIL, nil
}

func triggerAlert(event *models.ComplianceNotification) error {
	if !aws.BoolValue(event.ShouldAlert) {
		zap.L().Info("skipping alert notification",
			zap.String("policyId", *event.PolicyID))
		return nil
	}
	timeNow := time.Now().Unix()
	expiresAt := int64(alertSuppressPeriod) + timeNow

	alertConfig, err := getAlertConfigPolicy(event)
	if err != nil {
		zap.L().Warn("Encountered issue when getting policy",
			zap.Any("policyId", event.PolicyID))
		return err
	}

	marshalledAlertConfig, err := jsoniter.Marshal(alertConfig)
	if err != nil {
		zap.L().Error("failed to marshall alerting config", zap.Error(err))
		return err
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
		return err
	}

	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(ddbTable),
		Key: map[string]*dynamodb.AttributeValue{
			"policyId": {S: event.PolicyID},
		},
		UpdateExpression:          combinedExpression.Update(),
		ConditionExpression:       combinedExpression.Condition(),
		ExpressionAttributeNames:  combinedExpression.Names(),
		ExpressionAttributeValues: combinedExpression.Values(),
	}

	zap.L().Info("updating recent alerts table",
		zap.String("policyId", *event.PolicyID))
	_, err = ddbClient.UpdateItem(input)
	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			zap.L().Info("update on ddb failed on condition, we will not trigger an alert")
			return nil
		}
		zap.L().Warn("experienced issue while updating ddb table", zap.Error(err))
		return err
	}
	return nil
}

func triggerRemediation(event *models.ComplianceNotification) error {
	zap.L().Info("Triggering auto-remediation ",
		zap.String("policyId", *event.PolicyID),
		zap.String("resourceId", *event.ResourceID),
	)

	_, err := remediationClient.Operations.RemediateResourceAsync(
		&remediationoperations.RemediateResourceAsyncParams{
			Body: &remediationmodels.RemediateResource{
				PolicyID:   remediationmodels.PolicyID(*event.PolicyID),
				ResourceID: remediationmodels.ResourceID(*event.ResourceID),
			},
			HTTPClient: httpClient,
		})

	if err != nil {
		zap.L().Warn("failed to trigger remediation", zap.Error(err))
		return err
	}

	zap.L().Info("successfully triggered auto-remediation action")
	return nil
}

func getAlertConfigPolicy(event *models.ComplianceNotification) (*alertmodel.Alert, error) {
	policy, err := policyClient.Operations.GetPolicy(&analysisoperations.GetPolicyParams{
		ID:         *event.PolicyID,
		HTTPClient: httpClient,
	})

	if err != nil {
		return nil, err
	}

	return &alertmodel.Alert{
		CreatedAt:         event.Timestamp,
		PolicyDescription: aws.String(string(policy.Payload.Description)),
		PolicyID:          event.PolicyID,
		PolicyName:        aws.String(string(policy.Payload.DisplayName)),
		PolicyVersionID:   event.PolicyVersionID,
		Runbook:           aws.String(string(policy.Payload.Runbook)),
		Severity:          aws.String(string(policy.Payload.Severity)),
		Tags:              aws.StringSlice(policy.Payload.Tags),
		Type:              aws.String(alertmodel.PolicyType),
	}, nil
}
