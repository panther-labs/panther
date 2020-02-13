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

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/organization/models"
)

// CreateOrganization generates a new organization ID.
func (API) CreateOrganization(
	input *models.CreateOrganizationInput) (*models.CreateOrganizationOutput, error) {

	// Then write the new org to the Dynamo table
	org := &models.Organization{
		AlertReportFrequency:  input.AlertReportFrequency,
		AwsConfig:             input.AwsConfig,
		CreatedAt:             aws.String(time.Now().Format(time.RFC3339)),
		DisplayName:           input.DisplayName,
		Email:                 input.Email,
		ErrorReportingConsent: input.ErrorReportingConsent,
		Phone:                 input.Phone,
	}

	if err := orgTable.Put(org); err != nil {
		return nil, err
	}
	return &models.CreateOrganizationOutput{Organization: org}, nil
}
