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
	"github.com/stretchr/testify/mock"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
)

type mockOutputsClient struct {
	outputs.API
	mock.Mock
}

func (m *mockOutputsClient) Slack(
	ctx context.Context,
	alert *deliverymodel.Alert,
	config *outputModels.SlackConfig,
) *outputs.AlertDeliveryResponse {

	args := m.Called(ctx, alert, config)
	return args.Get(0).(*outputs.AlertDeliveryResponse)
}

func sampleAlert() *deliverymodel.Alert {
	return &deliverymodel.Alert{
		AlertID:      aws.String("alert-id"),
		Type:         deliverymodel.RuleType,
		OutputIds:    []string{"output-id"},
		Severity:     "INFO",
		AnalysisID:   "test-rule-id",
		AnalysisName: aws.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}
}
