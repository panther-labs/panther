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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	rulemodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

func TestUpdateAlertDelivery(t *testing.T) {
	t.Parallel()
	api := initTestAPI()

	alertID := "alertId"
	deliveryResponse := &models.DeliveryResponse{
		OutputID: "output-id",
		Message:  "successful delivery",
		Success:  true,
	}

	// Mocking table interactions
	input := &models.UpdateAlertDeliveryInput{
		AlertID:           alertID,
		DeliveryResponses: []*models.DeliveryResponse{},
	}
	output := &table.AlertItem{
		AlertID:           alertID,
		Type:              "RULE",
		RuleID:            "ruleId",
		RuleVersion:       "ruleVersion",
		DeliveryResponses: []*models.DeliveryResponse{deliveryResponse},
	}
	api.mockTable.On("UpdateAlertDelivery", input).Return(output, nil).Once()

	api.mockRuleCache.On("Get", "ruleId", "ruleVersion").Return(&rulemodels.Rule{}, nil).Once()

	expectedSummary := &models.AlertSummary{
		AlertID:           alertID,
		DeliveryResponses: []*models.DeliveryResponse{deliveryResponse},
	}

	result, err := api.UpdateAlertDelivery(input)
	assert.NoError(t, err)

	// Marshal to convert "" to nils and focus on our properties
	resultSummary := &models.AlertSummary{
		AlertID:           result.AlertID,
		DeliveryResponses: result.DeliveryResponses,
	}
	assert.Equal(t, expectedSummary, resultSummary)

	api.AssertExpectations(t)
}
