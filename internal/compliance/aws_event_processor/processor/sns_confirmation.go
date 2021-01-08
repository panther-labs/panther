package processor

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"go.uber.org/zap"
)

// SNS client factory that can be replaced for unit tests.
var snsClientBuilder = buildSnsClient

// Confirm the SNS subscription if the source account is a registered customer.
//
// Returns an error only if the confirmation failed and needs to be retried.
func handleSnsConfirmation(topicArn arn.ARN, token *string) error {
	if _, ok := accounts[topicArn.AccountID]; !ok {
		zap.L().Warn("refusing sns confirmation from unknown account",
			zap.String("accountId", topicArn.AccountID))
		return nil
	}

	if aws.StringValue(token) == "" {
		zap.L().Warn("no sns confirmation token", zap.String("topicArn", topicArn.String()))
		return nil
	}

	zap.L().Info("confirming sns subscription", zap.String("topicArn", topicArn.String()))
	snsClient, err := snsClientBuilder(&topicArn.Region)
	if err != nil {
		zap.L().Error("sns client creation failed", zap.Error(err))
		return err // retry session creation
	}

	response, err := snsClient.ConfirmSubscription(
		&sns.ConfirmSubscriptionInput{Token: token, TopicArn: aws.String(topicArn.String())})
	if err != nil {
		zap.L().Error("sns confirmation failed", zap.Error(err))
		return err // retry confirmation
	}

	zap.L().Info("sns subscription confirmed successfully",
		zap.String("subscriptionArn", aws.StringValue(response.SubscriptionArn)))
	return nil
}

func buildSnsClient(region *string) (snsiface.SNSAPI, error) {
	sess, err := session.NewSession(&aws.Config{Region: region})
	if err != nil {
		return nil, err
	}

	return sns.New(sess), nil
}
