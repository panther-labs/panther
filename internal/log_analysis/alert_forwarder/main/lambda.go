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
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/alert_forwarder/forwarder"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var validate = validator.New()

func main() {
	lambda.Start(reporterHandler)
}

func reporterHandler(ctx context.Context, event events.DynamoDBEvent) error {
	lambdalogger.ConfigureGlobal(ctx, nil)

	for _, record := range event.Records {
		event, err := forwarder.FromDynamodDBAttribute(record.Change.OldImage)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshall new image")
		}

		if err := forwarder.Process(event); err != nil {
			return errors.Wrap(err, "encountered issue while handling event")
		}
	}
	return nil
}
