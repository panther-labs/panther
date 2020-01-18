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

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyKMS(detail gjson.Result, accountID string) []*resourceChange {
	eventName := detail.Get("eventName").Str

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awskeymanagementservice.html
	if strings.HasPrefix(eventName, "Decrypt") ||
		strings.HasPrefix(eventName, "GenerateDataKey") ||
		strings.HasPrefix(eventName, "Encrypt") {

		zap.L().Debug("kms: ignoring event", zap.String("eventName", eventName))
		return nil
	}

	var keyARN string
	switch eventName {
	/*
		Missing (not sure if needed in all cases):
			(Connect/Create/Delete/Update)CustomKeyStore
			(Delete/Import)KeyMaterial
			(Retire/Revoke)Grant
	*/
	case "CancelKeyDeletion", "CreateGrant", "CreateKey", "DisableKey", "DisableKeyRotation", "EnableKey",
		"EnableKeyRotation", "PutKeyPolicy", "ScheduleKeyDeletion", "TagResource", "UntagResource",
		"UpdateAlias", "UpdateKeyDescription":
		keyARN = detail.Get("resources").Array()[0].Get("ARN").Str
	case "CreateAlias", "DeleteAlias":
		resources := detail.Get("resources").Array()
		for _, resource := range resources {
			resourceARN, err := arn.Parse(resource.Get("ARN").Str)
			if err != nil {
				zap.L().Error("kms: unable to extract ARN", zap.String("eventName", eventName))
				return nil
			}
			if strings.HasPrefix(resourceARN.Resource, "key/") {
				keyARN = resourceARN.String()
			}
		}
	default:
		zap.L().Warn("kms: encountered unknown event name", zap.String("eventName", eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: accountID,
		Delete:       eventName == "DeleteKey",
		EventName:    eventName,
		ResourceID:   keyARN,
		ResourceType: schemas.KmsKeySchema,
	}}
}
