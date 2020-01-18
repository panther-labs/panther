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

	"github.com/panther-labs/panther/internal/compliance/alert_forwarder/forwarder"
	"github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

const alertConfigKey = "alertConfig"

var validate = validator.New()

func main() {
	lambda.Start(reporterHandler)
}

func reporterHandler(ctx context.Context, event events.DynamoDBEvent) error {
	_, logger := lambdalogger.ConfigureGlobal(ctx, nil)

	for _, record := range event.Records {
		if record.Change.NewImage == nil {
			logger.Warn("Skipping records")
			continue
		}
		var alert models.Alert
		if err := jsoniter.Unmarshal(record.Change.NewImage[alertConfigKey].Binary(), &alert); err != nil {
			logger.Warn("Failed to unmarshall ddb stream item", zap.Error(err))
			return err
		}

		if err := validate.Struct(alert); err != nil {
			logger.Error("invalid message received", zap.Error(err))
			continue
		}

		if err := forwarder.Handle(&alert); err != nil {
			return err
		}
	}
	return nil
}
