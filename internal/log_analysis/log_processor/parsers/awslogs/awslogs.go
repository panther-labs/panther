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
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
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

	parsers.RegisterPantherLogPrefix("AWS", func(typ string, tm time.Time, fields ...parsers.PantherField) interface{} {
		p := parsers.NewPantherLog(typ, tm)
		ap := AWSPantherLog{
			PantherLog: *p,
		}
		ap.ExtendPantherFields(fields...)
		return &ap
	})

	parsers.RegisterPantherField(KindAWSARN, ARN)
	parsers.RegisterPantherField(KindAWSInstanceID, InstanceID)
	parsers.RegisterPantherField(KindAWSAccountID, AccountID)
	parsers.RegisterPantherField(KindAWSTag, Tag)
}
