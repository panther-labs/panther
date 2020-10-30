package aws

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

	"github.com/aws/aws-sdk-go/service/guardduty"
)

const (
	GuardDutySchema     = "AWS.GuardDuty.Detector"
	GuardDutyMetaSchema = "AWS.GuardDuty.Detector.Meta"
)

// GuardDutyDetector contains information about a GuardDuty Detector
type GuardDutyDetector struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from guardduty.GetDetectorOutput
	FindingPublishingFrequency *string
	ServiceRole                *string
	Status                     *string
	UpdatedAt                  *time.Time

	// Additional fields
	Master *guardduty.Master
}

// GuardDutyMeta contains metadata about all GuardDuty detectors in an account.
type GuardDutyMeta struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Additional fields
	Detectors []*string
}
