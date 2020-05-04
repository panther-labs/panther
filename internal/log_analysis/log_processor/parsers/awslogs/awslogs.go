package awslogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
)

func init() {
	// Register log types
	parsers.MustRegister(
		LogTypeALB,
		LogTypeAuroraMySQLAudit,
		LogTypeCloudTrail,
		LogTypeCloudTrailInsight,
		LogTypeGuardDuty,
		LogTypeS3ServerAccess,
		LogTypeVPCFlow,
	)

	// parsers.RegisterPantherLogPrefix("AWS", )

	logs.RegisterPrefixMeta("AWS", NewMeta)
	// logs.RegisterPantherField(KindAWSInstanceID, InstanceID)
	// logs.RegisterPantherField(KindAWSAccountID, AccountID)
	// logs.RegisterPantherField(KindAWSTag, Tag)
}

func NewMeta(event *logs.Event) (interface{}, error) {
	return &Meta{
		Meta:                     logs.NewMeta(event),
		PantherAnyAWSARNs:        event.Values(KindAWSARN),
		PantherAnyAWSAccountIds:  event.Values(KindAWSAccountID),
		PantherAnyAWSInstanceIds: event.Values(KindAWSInstanceID),
		PantherAnyAWSTags:        event.Values(KindAWSTag),
	}, nil
}
