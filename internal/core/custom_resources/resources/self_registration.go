package resources

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
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	// Panther user ID for deployment (must be a valid UUID4)
	systemUserID = "00000000-0000-4000-8000-000000000000"

	cloudSecLabel      = "panther-account"
	logProcessingLabel = "panther-account" // this must be lowercase, no spaces to work correctly, see genLogProcessingLabel()
)

type SelfRegistrationProperties struct {
	AccountID          string `validate:"required,len=12"`
	AuditLogsBucket    string `validate:"required"`
	EnableCloudTrail   bool   `json:",string"`
	EnableGuardDuty    bool   `json:",string"`
	EnableS3AccessLogs bool   `json:",string"`
}

func customSelfRegistration(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props SelfRegistrationProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		return "custom:self-registration:singleton", nil, registerPantherAccount(props)

	default:
		// ignore deletes
		return event.PhysicalResourceID, nil, nil
	}
}

func registerPantherAccount(props SelfRegistrationProperties) error {
	zap.L().Info("registering account with Panther for monitoring",
		zap.String("accountID", props.AccountID))

	// avoid alarms/errors and check first if the integrations exist
	var listOutput []*models.SourceIntegration
	var listInput = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{},
	}
	if err := genericapi.Invoke(getLambdaClient(), "panther-source-api", listInput, &listOutput); err != nil {
		return fmt.Errorf("error calling source-api to list integrations: %v", err)
	}

	// Check if registered
	registerCloudSec, registerLogProcessing := true, true
	for _, integration := range listOutput {
		if aws.StringValue(integration.AWSAccountID) == props.AccountID &&
			*integration.IntegrationType == models.IntegrationTypeAWSScan {

			zap.L().Info("account already registered for cloud security",
				zap.String("accountID", props.AccountID))
			registerCloudSec = false
		}
		if aws.StringValue(integration.AWSAccountID) == props.AccountID &&
			*integration.IntegrationType == models.IntegrationTypeAWS3 &&
			*integration.IntegrationLabel == genLogProcessingLabel() {

			zap.L().Info("account already registered for log processing",
				zap.String("accountID", props.AccountID))
			registerLogProcessing = false
		}
	}

	if registerCloudSec {
		input := &models.LambdaInput{
			PutIntegration: &models.PutIntegrationInput{
				PutIntegrationSettings: models.PutIntegrationSettings{
					AWSAccountID:       &props.AccountID,
					IntegrationLabel:   aws.String(cloudSecLabel),
					IntegrationType:    aws.String(models.IntegrationTypeAWSScan),
					ScanIntervalMins:   aws.Int(1440),
					UserID:             aws.String(systemUserID),
					CWEEnabled:         aws.Bool(true),
					RemediationEnabled: aws.Bool(true),
				},
			},
		}
		if err := genericapi.Invoke(getLambdaClient(), "panther-source-api", input, nil); err != nil &&
			!strings.Contains(err.Error(), "already onboarded") {

			return fmt.Errorf("error calling source-api to register account for cloud security: %v", err)
		}
		zap.L().Info("account registered for cloud security",
			zap.String("accountID", props.AccountID))
	}

	if registerLogProcessing {
		logTypes := []string{"AWS.VPCFlow", "AWS.ALB"}
		if props.EnableCloudTrail {
			logTypes = append(logTypes, "AWS.CloudTrail")
		}
		if props.EnableGuardDuty {
			logTypes = append(logTypes, "AWS.GuardDuty")
		}
		if props.EnableS3AccessLogs {
			logTypes = append(logTypes, "AWS.S3ServerAccess")
		}

		input := &models.LambdaInput{
			PutIntegration: &models.PutIntegrationInput{
				PutIntegrationSettings: models.PutIntegrationSettings{
					AWSAccountID:     &props.AccountID,
					IntegrationLabel: aws.String(genLogProcessingLabel()),
					IntegrationType:  aws.String(models.IntegrationTypeAWS3),
					UserID:           aws.String(systemUserID),
					S3Bucket:         &props.AuditLogsBucket,
					LogTypes:         aws.StringSlice(logTypes),
				},
			},
		}

		if err := genericapi.Invoke(getLambdaClient(), "panther-source-api", input, nil); err != nil &&
			!strings.Contains(err.Error(), "already onboarded") {

			return fmt.Errorf("error calling source-api to register account for log processing: %v", err)
		}
		zap.L().Info("account registered for log processing",
			zap.String("accountID", props.AccountID))
	}

	return nil
}

// make label regionally unique
func genLogProcessingLabel() string {
	return logProcessingLabel + "-" + *getSession().Config.Region
}
