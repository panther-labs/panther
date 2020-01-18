package main

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
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/core/alert_delivery/delivery"
	"github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var validate = validator.New()

func lambdaHandler(ctx context.Context, event events.SQSEvent) {
	_, logger := lambdalogger.ConfigureGlobal(ctx, nil)
	var alerts []*models.Alert

	for _, record := range event.Records {
		alert := &models.Alert{}
		if err := jsoniter.UnmarshalFromString(record.Body, alert); err != nil {
			logger.Error("failed to parse SQS message", zap.Error(err))
			continue
		}
		if err := validate.Struct(alert); err != nil {
			logger.Error("invalid message received", zap.Error(err))
			continue
		}
		alerts = append(alerts, alert)
	}

	if len(alerts) > 0 {
		delivery.HandleAlerts(alerts)
	} else {
		logger.Info("no alerts to process")
	}
}

func main() {
	lambda.Start(lambdaHandler)
}
