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

// Action defines an action the organization took
type Action = string

const (
	// VisitedOnboardingFlow defines when an organization visited the onboarding flow
	VisitedOnboardingFlow Action = "VISITED_ONBOARDING_FLOW"
)

// Organization defines the fields in the table row.
type Organization struct {
	AlertReportFrequency  *string    `json:"alertReportFrequency"`
	AwsConfig             *AwsConfig `json:"awsConfig"`
	CompletedActions      []*Action  `dynamodbav:"completedActions,omitempty,stringset" json:"completedActions"`
	CreatedAt             *string    `json:"createdAt"`
	DisplayName           *string    `json:"displayName"`
	Email                 *string    `json:"email"`
	ErrorReportingConsent *bool      `json:"errorReportingConsent"`
	Phone                 *string    `json:"phone"`
}

// AwsConfig defines metadata related to AWS infrastructure for the organization
type AwsConfig struct {
	UserPoolID     *string `json:"userPoolId"`
	AppClientID    *string `json:"appClientId"`
	IdentityPoolID *string `json:"identityPoolId"`
}
