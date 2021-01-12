package scheduler

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const sourceAPIFunctionName = "panther-source-api"

var (
	sess                               = session.Must(session.NewSession())
	lambdaClient lambdaiface.LambdaAPI = lambda.New(sess)
)

// PollAndIssueNewScans sends messages to the snapshot-pollers when new scans need to start.
func PollAndIssueNewScans() error {
	enabledIntegrations, err := GetEnabledIntegrations()
	if err != nil {
		return err
	}
	if len(enabledIntegrations) == 0 {
		zap.L().Info("no scans to schedule")
		return nil
	}

	zap.L().Info("loaded enabled integrations", zap.Int("count", len(enabledIntegrations)))
	var integrationsToScan []*models.SourceIntegrationMetadata

	for _, integration := range enabledIntegrations {
		// Only add new scans if needed
		if (scanIntervalElapsed(integration) && scanIsNotOngoing(integration)) || scanIsStuck(integration) {
			integrationsToScan = append(integrationsToScan, &integration.SourceIntegrationMetadata)
		} else {
			zap.L().Debug("skipping integration", zap.String("integrationID", integration.IntegrationID))
		}
	}

	return genericapi.Invoke(
		lambdaClient,
		sourceAPIFunctionName,
		&models.LambdaInput{FullScan: &models.FullScanInput{
			Integrations: integrationsToScan,
		}},
		nil,
	)
}

// GetEnabledIntegrations lists enabled integrations from the snapshot-api.
func GetEnabledIntegrations() (integrations []*models.SourceIntegration, err error) {
	err = genericapi.Invoke(
		lambdaClient,
		sourceAPIFunctionName,
		&models.LambdaInput{ListIntegrations: &models.ListIntegrationsInput{
			IntegrationType: aws.String("aws-scan"),
		}},
		&integrations,
	)

	return
}

// scanIsStuck checks if an integration's is stuck in the "scanning" state.
func scanIsStuck(integration *models.SourceIntegration) bool {
	// Accounts for a new integration that has not completed a scan
	if integration.LastScanEndTime.IsZero() {
		return false
	}

	return integration.ScanStatus == models.StatusScanning && scanIntervalElapsed(integration)
}

// scanIsNotOngoing checks if an integration's snapshot is currently running.
func scanIsNotOngoing(integration *models.SourceIntegration) bool {
	return integration.ScanStatus != models.StatusScanning
}

// scanIntervalElapsed determines if a new scan needs to be started based on the configured interval.
func scanIntervalElapsed(integration *models.SourceIntegration) bool {
	if integration.LastScanEndTime == nil {
		return true
	}

	intervalMins := time.Duration(integration.ScanIntervalMins) * time.Minute
	return time.Since(*integration.LastScanEndTime) >= intervalMins
}
