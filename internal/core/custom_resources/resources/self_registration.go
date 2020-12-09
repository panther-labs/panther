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
	"sort"
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

	cloudSecLabel = "panther-account"
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
		return "custom:self-registration:" + props.AccountID, nil, registerPantherAccount(props)

	case cfn.RequestDelete:
		split := strings.Split(event.PhysicalResourceID, ":")
		accountID := split[len(split)-1]
		return event.PhysicalResourceID, nil, removeSelfIntegrations(accountID)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func registerPantherAccount(props SelfRegistrationProperties) error {
	zap.L().Info("registering account with Panther for monitoring",
		zap.String("accountID", props.AccountID))

	cloudSecSource, logSource, err := getSelfIntegrations(props.AccountID)
	if err != nil {
		return err
	}

	if cloudSecSource == nil {
		if err := putCloudSecurityIntegration(props.AccountID); err != nil {
			return err
		}
	}

	// collect the configured log types
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

	if logSource == nil {
		if err := putLogProcessingIntegration(props.AccountID, props.AuditLogsBucket, logTypes); err != nil {
			return err
		}
	} else if !stringSliceEqual(logSource.RequiredLogTypes(), logTypes) {
		// log types have changed, we need to update the source integration
		if err := updateLogProcessingIntegration(logSource, logTypes); err != nil {
			return err
		}
	}

	return nil
}

// make label regionally unique
func genLogProcessingLabel() string {
	return "panther-account-" + *awsSession.Config.Region
}

// Get the current Cloud Security and Log Processing self integrations from source-api.
func getSelfIntegrations(accountID string) (*models.SourceIntegration, *models.SourceIntegration, error) {
	var listOutput []*models.SourceIntegration
	var listInput = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{},
	}
	if err := genericapi.Invoke(lambdaClient, "panther-source-api", listInput, &listOutput); err != nil {
		return nil, nil, fmt.Errorf("error calling source-api to list integrations: %v", err)
	}

	var cloudSecSource, logSource *models.SourceIntegration
	for _, integration := range listOutput {
		if integration.AWSAccountID == accountID &&
			integration.IntegrationType == models.IntegrationTypeAWSScan {

			cloudSecSource = integration
		} else if integration.AWSAccountID == accountID &&
			integration.IntegrationType == models.IntegrationTypeAWS3 &&
			integration.IntegrationLabel == genLogProcessingLabel() {

			logSource = integration
		}
	}

	return cloudSecSource, logSource, nil
}

// Returns true if the two string slices have the same elements in any order.
//
// The input slices may be sorted as a side effect.
func stringSliceEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	sort.Strings(left)
	sort.Strings(right)
	for i, elem := range left {
		if right[i] != elem {
			return false
		}
	}

	return true
}

func putCloudSecurityIntegration(accountID string) error {
	input := &models.LambdaInput{
		PutIntegration: &models.PutIntegrationInput{
			PutIntegrationSettings: models.PutIntegrationSettings{
				AWSAccountID:       accountID,
				IntegrationLabel:   cloudSecLabel,
				IntegrationType:    models.IntegrationTypeAWSScan,
				ScanIntervalMins:   1440,
				UserID:             systemUserID,
				CWEEnabled:         aws.Bool(true),
				RemediationEnabled: aws.Bool(true),
			},
		},
	}

	if err := genericapi.Invoke(lambdaClient, "panther-source-api", input, nil); err != nil &&
		!strings.Contains(err.Error(), "already onboarded") {

		return fmt.Errorf("error calling source-api to register account for cloud security: %v", err)
	}

	zap.L().Info("account registered for cloud security", zap.String("accountID", accountID))
	return nil
}

func putLogProcessingIntegration(accountID, auditBucket string, logTypes []string) error {
	input := &models.LambdaInput{
		PutIntegration: &models.PutIntegrationInput{
			PutIntegrationSettings: models.PutIntegrationSettings{
				AWSAccountID:     accountID,
				IntegrationLabel: genLogProcessingLabel(),
				IntegrationType:  models.IntegrationTypeAWS3,
				UserID:           systemUserID,
				S3Bucket:         auditBucket,
				LogTypes:         logTypes,
			},
		},
	}

	if err := genericapi.Invoke(lambdaClient, "panther-source-api", input, nil); err != nil &&
		!strings.Contains(err.Error(), "already onboarded") {

		return fmt.Errorf("error calling source-api to register account for log processing: %v", err)
	}

	zap.L().Info("account registered for log processing",
		zap.String("accountID", accountID), zap.String("bucket", auditBucket),
		zap.Strings("logTypes", logTypes))
	return nil
}

func updateLogProcessingIntegration(source *models.SourceIntegration, logTypes []string) error {
	input := &models.LambdaInput{
		UpdateIntegrationSettings: &models.UpdateIntegrationSettingsInput{
			IntegrationID:    source.IntegrationID,
			IntegrationLabel: source.IntegrationLabel,
			S3Bucket:         source.S3Bucket,
			S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "", LogTypes: logTypes}},
		},
	}

	if err := genericapi.Invoke(lambdaClient, "panther-source-api", input, nil); err != nil {
		return fmt.Errorf("error calling source-api to update account for log processing: %v", err)
	}

	zap.L().Info("account updated for log processing",
		zap.String("accountID", source.AWSAccountID),
		zap.String("bucket", source.S3Bucket),
		zap.Strings("logTypes", logTypes))
	return nil
}

func removeSelfIntegrations(accountID string) error {
	cloudSecSource, logSource, err := getSelfIntegrations(accountID)
	if err != nil {
		return err
	}

	if cloudSecSource != nil {
		if err = deleteIntegration(cloudSecSource); err != nil {
			return err
		}
	}

	if logSource != nil {
		if err = deleteIntegration(logSource); err != nil {
			return err
		}
	}

	return nil
}

func deleteIntegration(source *models.SourceIntegration) error {
	zap.L().Info("deleting source integration",
		zap.String("integrationID", source.IntegrationID),
		zap.String("integrationLabel", source.IntegrationLabel))

	input := models.LambdaInput{
		DeleteIntegration: &models.DeleteIntegrationInput{
			IntegrationID: source.IntegrationID,
		},
	}
	return genericapi.Invoke(lambdaClient, "panther-source-api", &input, nil)
}
