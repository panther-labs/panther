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
	"github.com/aws/aws-sdk-go/aws/session"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/gateway/remediation/models"
	"github.com/panther-labs/panther/internal/compliance/remediation_api/remediation"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var invoker = remediation.NewInvoker(session.Must(session.NewSession()))

func main() {
	lambda.Start(lambdaHandler)
}

func lambdaHandler(ctx context.Context, event events.SQSEvent) error {
	lambdalogger.ConfigureGlobal(ctx, nil)

	for _, record := range event.Records {
		var input models.RemediateResource
		if err := jsoniter.UnmarshalFromString(record.Body, &input); err != nil {
			return err
		}
		if err := invoker.Remediate(&input); err != nil {
			return err
		}
	}
	return nil
}
