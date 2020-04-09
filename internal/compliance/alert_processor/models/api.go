package models

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
)

// ComplianceNotification represents the event sent to the AlertProcessor by the compliance engine.
type ComplianceNotification struct {

	//ResourceID is the ID specific to the resource
	ResourceID *string `json:"resourceId" validate:"required,min=1"`

	//PolicyID is the id of the policy that triggered
	PolicyID *string `json:"policyId" validate:"required,min=1"`

	//PolicyVersionID is the version of policy when the alert triggered
	PolicyVersionID *string `json:"policyVersionId"`

	//ShouldAlert indicates whether this notification should cause an alert to be send to the customer
	ShouldAlert *bool `json:"shouldAlert"`

	//Timestamp indicates when the policy was actually evaluated
	Timestamp *time.Time `json:"timestamp"`
}
