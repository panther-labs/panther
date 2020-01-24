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
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/alert_merger/merger"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var validate = validator.New()

func main() {
	lambda.Start(Handler)
}

// Handler is the entry point for the alert merger Lambda
func Handler(ctx context.Context, event events.SQSEvent) error {
	_, logger := lambdalogger.ConfigureGlobal(ctx, nil)

	var recordCount, errorCount int

	operation := common.OpLogManager.Start("alertMerger")
	defer func() {
		operation.Stop()
		var err error
		if errorCount > 0 {
			err = errors.New("failures merging alerts")
		}
		operation.Log(err,
			zap.Int("recordCount", recordCount),
			zap.Int("errorCount", errorCount))
	}()

	for _, record := range event.Records {
		recordCount++

		input := &merger.AlertNotification{}
		if err := jsoniter.UnmarshalFromString(record.Body, input); err != nil {
			errorCount++
			logger.Error("failed to unmarshal event", zap.Error(err), zap.Any("event", record))
			continue // skip bad data, nothing to be done
		}

		if err := validate.Struct(input); err != nil {
			errorCount++
			logger.Error("invalid message received", zap.Error(err), zap.Any("input", input))
			continue // skip bad data, nothing to be done
		}

		// this is where real work is done, for safety, fail lambda on any error
		if err := merger.Handle(input); err != nil {
			errorCount++
			logger.Error("encountered issue while processing event", zap.Error(err), zap.Any("input", input))
			return err
		}
	}
	return nil
}
