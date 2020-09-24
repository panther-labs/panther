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

// LambdaInput is the request structure for the organization-api Lambda function.
type LambdaInput struct {
	GetSettings    *GetSettingsInput    `json:"getSettings"`
	UpdateSettings *UpdateSettingsInput `json:"updateSettings"`
}

// GetSettingsInput retrieves general account settings.
type GetSettingsInput struct{}

// UpdateSettingsInput modifies one or more settings.
//
// Only non-nil fields are updated.
type UpdateSettingsInput = GeneralSettings

// GeneralSettings defines basic settings for a Panther deployment.
type GeneralSettings struct {
	DisplayName           *string `json:"displayName" validate:"omitempty,min=1,excludesall='<>&\""`
	Email                 *string `genericapi:"redact" json:"email" validate:"omitempty,email"`
	ErrorReportingConsent *bool   `json:"errorReportingConsent"`
	AnalyticsConsent      *bool   `json:"analyticsConsent"`
}
