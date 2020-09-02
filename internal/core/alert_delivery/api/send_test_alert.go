package api

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
	"go.uber.org/zap"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
)

// SendTestAlert sends a dummy alert to the specified destinations.
func (API) SendTestAlert(input *deliveryModels.SendTestAlertInput) (*deliveryModels.SendTestAlertOutput, error) {
	// First, fetch the alert
	zap.L().Debug("Sending test alert")

	// Fetch the Policy or Rule associated with the alert to fill in the missing attributes
	alert := generateTestAlert()

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMapping(alert, input.OutputIds)
	if err != nil {
		return &deliveryModels.SendTestAlertOutput{
			Success: false,
		}, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := sendAlerts(alertOutputMap)

	// Log any failures and return
	if err := returnIfFailed(dispatchStatuses); err != nil {
		return &deliveryModels.SendTestAlertOutput{
			Success: false,
		}, err
	}
	zap.L().Debug("Test Succeeded")
	return &deliveryModels.SendTestAlertOutput{
		Success: true,
	}, nil
}

// generateTestAlert - genreates an alert with dummy values
func generateTestAlert() *deliveryModels.Alert {
	return &deliveryModels.Alert{
		AnalysisID:          "Test.Alert",
		Type:                deliveryModels.RuleType,
		CreatedAt:           time.Now().UTC(),
		Severity:            "INFO",
		OutputIds:           []string{},
		AnalysisDescription: aws.String("This is a Test Alert"),
		AnalysisName:        aws.String("Test Alert"),
		Version:             aws.String("abcdefg"),
		Runbook:             aws.String("Stuck? Check out our docs: https://docs.runpanther.io"),
		Tags:                []string{"test"},
		AlertID:             aws.String("Test.Alert"),
		Title:               aws.String("This is a Test Alert"),
		RetryCount:          0,
		IsTest:              true,
		IsResent:            false,
	}
}
