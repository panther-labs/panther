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

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyKMS(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awskeymanagementservice.html
	var keyARN string
	switch metadata.eventName {
	/*
		Missing (not sure if needed in all cases):
			(Connect/Create/Delete/Update)CustomKeyStore
			(Delete/Import)KeyMaterial
			(Retire/Revoke)Grant
	*/
	case "CancelKeyDeletion",
		"CreateAlias",
		"CreateGrant",
		"CreateKey",
		"DeleteKey",
		"DeleteAlias",
		"DisableKey",
		"DisableKeyRotation",
		"EnableKey",
		"EnableKeyRotation",
		"PutKeyPolicy",
		"ScheduleKeyDeletion",
		"TagResource",
		"UntagResource",
		"UpdateAlias",
		"UpdateKeyDescription":
		keyARN = getKeyARN(detail)
	default:
		zap.L().Info("kms: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	if keyARN == "" {
		zap.L().Warn("kms: missing arn", zap.String("eventName", metadata.eventName), zap.Any("detail", detail))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteKey",
		EventName:    metadata.eventName,
		ResourceID:   keyARN,
		ResourceType: schemas.KmsKeySchema,
	}}
}

func getKeyARN(detail gjson.Result) (keyARN string) {
	resources := detail.Get("resources").Array()
	for _, resource := range resources {
		resourceARN, err := arn.Parse(resource.Get("arn").Str)
		if err == nil && strings.HasPrefix(resourceARN.Resource, "key/") {
			keyARN = resourceARN.String()
			break
		}
	}
	return keyARN
}
