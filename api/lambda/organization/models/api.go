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

// LambdaInput is the request structure for the organization-api Lambda function.
type LambdaInput struct {
	CompleteAction     *CompleteActionInput     `json:"getCompletedActions"`
	CreateOrganization *CreateOrganizationInput `json:"createOrganization"`
	GetOrganization    *GetOrganizationInput    `json:"getOrganization"`
	UpdateOrganization *UpdateOrganizationInput `json:"updateOrganization"`
}

// CompleteActionInput Adds a Action to an Organization
type CompleteActionInput struct {
	CompletedActions []*Action `json:"actions"`
}

// CompleteActionOutput Adds a Action to an Organization
type CompleteActionOutput struct {
	CompletedActions []*Action `json:"actions"`
}

// CreateOrganizationInput creates a new Panther customer account.
type CreateOrganizationInput struct {
	AlertReportFrequency  *string    `json:"alertReportFrequency" validate:"omitempty,oneof=P1D P1W"`
	AwsConfig             *AwsConfig `json:"awsConfig"`
	DisplayName           *string    `json:"displayName" validate:"required,min=1"`
	Email                 *string    `genericapi:"redact" json:"email" validate:"required,email"`
	ErrorReportingConsent *bool      `json:"errorReportingConsent"`
	Phone                 *string    `genericapi:"redact" json:"phone"`
}

// CreateOrganizationOutput returns the newly created organization.
type CreateOrganizationOutput struct {
	Organization *Organization `json:"organization"`
}

// GetOrganizationInput retrieves the details of a Panther customer account.
type GetOrganizationInput struct {
}

// GetOrganizationOutput is the table row representing a customer account.
type GetOrganizationOutput struct {
	Organization *Organization `json:"organization"`
}

// UpdateOrganizationInput modifies the details of an existing organization.
type UpdateOrganizationInput struct {
	CreateOrganizationInput
}

// UpdateOrganizationOutput is the table row representing the modified customer account.
type UpdateOrganizationOutput struct {
	Organization *Organization `json:"organization"`
}
