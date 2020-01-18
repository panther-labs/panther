package processor

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
	"strings"

	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyConfig(detail gjson.Result, accountID string) []*resourceChange {
	eventName := detail.Get("eventName").Str

	// We need to add more config resources, just a config recorder is too high level
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awsconfig.html
	if eventName == "PutAggregationAuthorization" ||
		eventName == "PutConfigurationAggregator" ||
		eventName == "PutDeliveryChannel" ||
		eventName == "PutEvaluations" ||
		eventName == "PutRemediationConfigurations" ||
		eventName == "PutRetentionConfiguration" ||
		eventName == "StartRemediationExecution" ||
		eventName == "TagResource" ||
		eventName == "UntagResource" ||
		eventName == "DeleteDeliveryChannel" ||
		eventName == "DeleteEvaluationResults" ||
		eventName == "DeletePendingAggregationRequest" ||
		eventName == "DeleteRemediationConfiguration" ||
		eventName == "DeleteRetentionConfiguration" ||
		eventName == "DeliverConfigSnapshot" ||
		eventName == "DeleteAggregationAuthorization" ||
		eventName == "DeleteConfigRule" ||
		eventName == "DeleteConfigurationAggregator" ||
		eventName == "PutConfigRule" {

		zap.L().Debug("config: ignoring event", zap.String("eventName", eventName))
		return nil
	}

	switch eventName {
	case "StartConfigRulesEvaluation", "StartConfigurationRecorder", "StopConfigurationRecorder":
		// This case handles when a recorder is updated in a way that does not require a full account
		// scan to update the config meta resource
		return []*resourceChange{{
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceID: strings.Join([]string{
				accountID,
				detail.Get("awsRegion").Str,
				schemas.ConfigServiceSchema,
			}, ":"),
			ResourceType: schemas.ConfigServiceSchema,
		}}
	case "PutConfigurationRecorder":
		// This case handles when a recorder is updated in a way that requires a full account scan
		// in order to update the config meta resource
		return []*resourceChange{{
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceType: schemas.ConfigServiceSchema,
		}}
	case "DeleteConfigurationRecorder":
		// Special case where need to queue both a delete action and a meta re-scan
		return []*resourceChange{
			{
				AwsAccountID: accountID,
				Delete:       true,
				EventName:    eventName,
				ResourceID: strings.Join([]string{
					accountID,
					detail.Get("awsRegion").Str,
					schemas.ConfigServiceSchema,
				}, ":"),
				ResourceType: schemas.ConfigServiceSchema,
			},
			{
				AwsAccountID: accountID,
				EventName:    eventName,
				ResourceType: schemas.ConfigServiceSchema,
			}}
	default:
		zap.L().Warn("config: encountered unknown event name", zap.String("eventName", eventName))
		return nil
	}
}
