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
	"context"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
)

// SendTestAlert sends a dummy alert to the specified destinations.
func (API) SendTestAlert(ctx context.Context, input *deliverymodel.SendTestAlertInput) ([]*deliverymodel.SendTestAlertOutput, error) {
	// First, fetch the alert
	zap.L().Debug("Sending test alert")

	// Fetch the Policy or Rule associated with the alert to fill in the missing attributes
	alert := generateTestAlert()

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMapping(alert, input.OutputIds)
	if err != nil {
		return nil, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := sendAlerts(ctx, alertOutputMap, outputClient)

	// Convert the full dispatch statuses into ones that are friendly for the frontend
	responseStatuses := []*deliverymodel.SendTestAlertOutput{}
	for _, status := range dispatchStatuses {
		responseStatuses = append(responseStatuses, &deliverymodel.SendTestAlertOutput{
			OutputID:     status.OutputID,
			Message:      status.Message,
			StatusCode:   status.StatusCode,
			Success:      status.Success,
			DispatchedAt: status.DispatchedAt,
		})
	}

	return responseStatuses, nil
}

// generateTestAlert - genreates an alert with dummy values
func generateTestAlert() *deliverymodel.Alert {
	return &deliverymodel.Alert{
		AnalysisID:          "Test.Alert",
		Type:                deliverymodel.RuleType,
		CreatedAt:           time.Now().UTC(),
		Severity:            "INFO",
		OutputIds:           []string{},
		AnalysisDescription: "This is a Test Alert",
		AnalysisName:        aws.String("Test Alert"),
		Version:             aws.String("abcdefg"),
		Runbook:             "Stuck? Check out our docs: https://docs.runpanther.io",
		Tags:                []string{"test"},
		AlertID:             aws.String("Test.Alert"),
		Title:               "This is a Test Alert",
		RetryCount:          0,
		IsTest:              true,
		IsResent:            false,
	}
}
