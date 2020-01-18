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
	"go.uber.org/zap"

	organizationmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// GetUserOrganizationAccess calls dynamodb to get user's organization id.
func (API) GetUserOrganizationAccess(input *models.GetUserOrganizationAccessInput) (*models.GetUserOrganizationAccessOutput, error) {
	// Delete user from Dynamo
	_, err := userTable.Get(input.Email)
	if err != nil {
		zap.L().Error("error getting user", zap.Error(err))
		return nil, err
	}
	org, err := GetOrganizations()
	if err != nil {
		zap.L().Error("error getting organization", zap.Error(err))
		return nil, err
	}
	return org, nil
}

// GetOrganizations calls the organization api to fetch access related identifiers
func GetOrganizations() (*models.GetUserOrganizationAccessOutput, error) {
	input := organizationmodels.LambdaInput{GetOrganization: &organizationmodels.GetOrganizationInput{}}
	var org organizationmodels.GetOrganizationOutput
	if err := genericapi.Invoke(lambdaClient, organizationAPI, &input, &org); err != nil {
		return nil, err
	}
	return &models.GetUserOrganizationAccessOutput{
		UserPoolID:     org.Organization.AwsConfig.UserPoolID,
		AppClientID:    org.Organization.AwsConfig.AppClientID,
		IdentityPoolID: org.Organization.AwsConfig.IdentityPoolID,
	}, nil
}
