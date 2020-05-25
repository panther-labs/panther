package processor

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
	"strings"

	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyConfig(_ gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// We need to add more config resources, just a config recorder is too high level
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awsconfig.html
	switch metadata.eventName {
	case "StartConfigRulesEvaluation", "StartConfigurationRecorder", "StopConfigurationRecorder":
		// This case handles when a recorder is updated in a way that does not require a full account
		// scan to update the config meta resource
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID: strings.Join([]string{
				metadata.accountID,
				metadata.region,
				schemas.ConfigServiceSchema,
			}, ":"),
			ResourceType: schemas.ConfigServiceSchema,
		}}
	case "PutConfigurationRecorder":
		// This case handles when a recorder is updated in a way that requires a full account scan
		// in order to update the config meta resource
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceType: schemas.ConfigServiceSchema,
		}}
	case "DeleteConfigurationRecorder":
		// Special case where need to queue both a delete action and a meta re-scan
		return []*resourceChange{
			{
				AwsAccountID: metadata.accountID,
				Delete:       true,
				EventName:    metadata.eventName,
				ResourceID: strings.Join([]string{
					metadata.accountID,
					metadata.region,
					schemas.ConfigServiceSchema,
				}, ":"),
				ResourceType: schemas.ConfigServiceSchema,
			},
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceType: schemas.ConfigServiceSchema,
			}}
	default:
		zap.L().Info("config: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}
}
