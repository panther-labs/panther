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

func classifyGuardDuty(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonguardduty.html
	if metadata.eventName == "ArchiveFindings" ||
		metadata.eventName == "CreateIPSet" ||
		metadata.eventName == "CreateSampleFindings" ||
		metadata.eventName == "CreateThreatIntelSet" ||
		metadata.eventName == "DeclineInvitations" ||
		metadata.eventName == "DeleteFilter" ||
		metadata.eventName == "DeleteIPSet" ||
		metadata.eventName == "DeleteInvitations" ||
		metadata.eventName == "DeleteThreatIntelSet" ||
		metadata.eventName == "InviteMembers" ||
		metadata.eventName == "UnarchiveFindings" ||
		metadata.eventName == "UpdateFilter" ||
		metadata.eventName == "UpdateFindingsFeedback" ||
		metadata.eventName == "UpdateIPSet" ||
		metadata.eventName == "UpdateThreatIntelSet" ||
		metadata.eventName == "CreateFilter" {

		zap.L().Debug("guardduty: ignoring event", zap.String("eventName", metadata.eventName))
		return nil
	}

	switch metadata.eventName {
	case "TagResource", "UntagResource", "UpdateDetector":
		// Single resource/region scan (only one detector can exist per region)
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID: strings.Join([]string{
				metadata.accountID,
				detail.Get("awsRegion").Str,
				schemas.GuardDutySchema,
			}, ":"),
			ResourceType: schemas.GuardDutySchema,
		}}
	case "AcceptInvitation", "CreateDetector", "CreateMembers", "DeleteMembers", "DisassociateFromMasterAccount",
		"DisassociateMembers", "StartMonitoringMembers", "StopMonitoringMembers":
		// Full account scan
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceType: schemas.GuardDutySchema,
		}}
	case "DeleteDetector":
		// Special case where need to queue both a delete action and a meta re-scan
		return []*resourceChange{
			{
				AwsAccountID: metadata.accountID,
				Delete:       true,
				EventName:    metadata.eventName,
				ResourceID: strings.Join([]string{
					metadata.accountID,
					detail.Get("awsRegion").Str,
					schemas.GuardDutySchema,
				}, ":"),
				ResourceType: schemas.GuardDutySchema,
			},
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceType: schemas.GuardDutySchema,
			}}
	default:
		zap.L().Warn("guardduty: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}
}
