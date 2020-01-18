package models

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

import "time"

// RuleType identifies the Alert to be for a Policy
const RuleType = "RULE"

// PolicyType identifies the Alert to be for a Policy
const PolicyType = "POLICY"

// Alert is the schema for each row in the Dynamo alerts table.
type Alert struct {

	// CreatedAt is the creation timestamp (seconds since epoch).
	CreatedAt *time.Time `json:"createdAt,omitempty"`

	// OutputIDs is the set of outputs for this alert.
	OutputIDs []*string `json:"outputIds,omitempty"`

	// PolicyDescription is the description of the rule that triggered the alert.
	PolicyDescription *string `json:"policyDescription,omitempty"`

	// PolicyID is the rule that triggered the alert.
	PolicyID *string `json:"policyId" validate:"required"`

	// PolicyName is the name of the policy at the time the alert was triggered.
	PolicyName *string `json:"policyName,omitempty"`

	// PolicyVersionID is the S3 object version for the policy.
	PolicyVersionID *string `json:"policyVersionId,omitempty"`

	// Runbook is the user-provided triage information.
	Runbook *string `json:"runbook,omitempty"`

	// Severity is the alert severity at the time of creation.
	Severity *string `json:"severity" validate:"required,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Tags is the set of policy tags.
	Tags []*string `json:"tags,omitempty"`

	// AlertID specifies the alertId that this Alert is associated with.
	AlertID *string `json:"alertId,omitempty"`

	// Type specifies if an alert is for a policy or a rule
	Type *string `json:"type,omitempty" validate:"omitempty,oneof=RULE POLICY"`
}
