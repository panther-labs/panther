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
	"github.com/go-playground/validator"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	delivery "github.com/panther-labs/panther/internal/core/alert_delivery/delivery"
)

var validate = validator.New()

// DispatchAlert - Sends an alert to sends a specific alert to the specified destinations.
func (API) DispatchAlert(input []*models.DispatchAlertsInput) (output interface{}, err error) {
	zap.L().Info("Dispatching alerts", zap.Int("num_alerts", len(input)))

	var alerts []*models.Alert
	for _, record := range input {
		alert := &models.Alert{}
		if err = jsoniter.UnmarshalFromString(record.Body, alert); err != nil {
			zap.L().Error("Failed to unmarshal item", zap.Error(err))
			continue
		}
		if err = validate.Struct(alert); err != nil {
			zap.L().Error("invalid message received", zap.Error(err))
			continue
		}
		alerts = append(alerts, alert)
	}
	delivery.HandleAlerts(alerts)
	return nil, err
}
