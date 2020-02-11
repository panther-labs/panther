package api

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

import "github.com/panther-labs/panther/api/lambda/organization/models"

// UpdateOrganization updates account details.
func (API) UpdateOrganization(
	input *models.UpdateOrganizationInput) (*models.UpdateOrganizationOutput, error) {

	updated, err := orgTable.Update(&models.Organization{
		AlertReportFrequency:  input.AlertReportFrequency,
		AwsConfig:             input.AwsConfig,
		DisplayName:           input.DisplayName,
		Email:                 input.Email,
		ErrorReportingConsent: input.ErrorReportingConsent,
		Phone:                 input.Phone,
	})
	if err != nil {
		return nil, err
	}

	return &models.UpdateOrganizationOutput{Organization: updated}, nil
}
