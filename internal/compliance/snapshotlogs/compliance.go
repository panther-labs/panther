package snapshotlogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

const TypeCompliance = "Compliance.History"

var logTypeComplianceHistory = logtypes.MustBuild(logtypes.ConfigJSON{
	Name:         TypeCompliance,
	Description:  `Contains Cloud Security compliance snapshots`,
	ReferenceURL: `https://docs.runpanther.io/cloud-security/overview`,
	NewEvent: func() interface{} {
		return &Compliance{}
	},
	Validate: pantherlog.ValidateStruct,
})

// nolint:lll
type Compliance struct {
	ChangeType       pantherlog.String `json:"changeType" validate:"required" description:"The type of change that initiated this snapshot creation."`
	IntegrationID    pantherlog.String `json:"integrationId" validate:"required" description:"The unique source ID of the account this resource lives in."`
	IntegrationLabel pantherlog.String `json:"integrationLabel" validate:"required" description:"The friendly source name of the account this resource lives in."`
	LastUpdated      pantherlog.Time   `json:"lastUpdated" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The time this snapshot occurred."`
	PolicyID         pantherlog.String `json:"policyId" validate:"required" description:"The unique ID of the policy evaluating the resource."`
	PolicySeverity   pantherlog.String `json:"policySeverity" validate:"required" description:"The severity of the policy evaluating the resource."`
	ResourceID       pantherlog.String `json:"resourceId" panther:"aws_arn" validate:"required" description:"The unique Panther ID of the resource being evaluated."`
	ResourceType     pantherlog.String `json:"resourceType" validate:"required" description:"The type of resource being evaluated."`
	Status           pantherlog.String `json:"status" validate:"required,oneof=PASS FAIL ERROR" description:"Whether this resource is passing, failing, or erroring on this policy."`
	Suppressed       pantherlog.Bool   `json:"suppressed" validate:"required" description:"Whether this resource is being ignored for the purpose of reports."`
}
