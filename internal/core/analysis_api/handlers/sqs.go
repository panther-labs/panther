package handlers

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

// Queue a policy for re-analysis (evaluate against all applicable resources).
//
// This ensures policy changes are reflected almost immediately (instead of waiting for daily scan).
func queuePolicy(policy *tableItem) error {
	body, err := jsoniter.MarshalToString(policy.Policy(""))
	if err != nil {
		zap.L().Error("failed to marshal policy", zap.Error(err))
		return err
	}

	zap.L().Info("queueing policy for analysis",
		zap.String("policyId", policy.ID),
		zap.String("resourceQueueURL", env.ResourceQueueURL))
	_, err = sqsClient.SendMessage(
		&sqs.SendMessageInput{MessageBody: &body, QueueUrl: &env.ResourceQueueURL})
	return err
}

// updateLayer sends a message to the layer manager lambda indicating a layer of a certain type
// needs to be re-built
//
// Currently only the global type is supported, but in the future we may support other types as
// well.
func updateLayer() error {
	_, err := sqsClient.SendMessage(&sqs.SendMessageInput{
		MessageBody: aws.String(string(models.TypeGlobal)),
		QueueUrl:    aws.String(env.LayerManagerQueueURL),
	})
	return err
}
