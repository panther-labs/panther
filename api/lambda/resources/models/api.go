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

	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

// LambdaInput is the request structure for the resources-api Lambda function.
type LambdaInput struct {
	AddResources    *AddResourcesInput    `json:"addResources"`
	GetResource     *GetResourceInput     `json:"getResource"`
	DeleteResources *DeleteResourcesInput `json:"deleteResources"`
	ListResources   *ListResourcesInput   `json:"listResources"`
}

// Backend adds or replaces resources
type AddResourcesInput struct {
	Resources []AddResourceEntry `json:"resources" validate:"min=1,dive"`
}

type AddResourceEntry struct {
	Attributes      interface{} `json:"attributes" validate:"required"`
	ID              string      `json:"id" validate:"required"`
	IntegrationID   string      `json:"integrationId" validate:"uuid4"`
	IntegrationType string      `json:"integrationType" validate:"oneof=aws"`
	Type            string      `json:"type" validate:"required"`
}

type GetResourceInput struct {
	ID string `json:"resourceId" validate:"required"`
}

type GetResourceOutput = Resource

type Resource struct {
	Attributes       interface{}             `json:"attributes"`
	ComplianceStatus models.ComplianceStatus `json:"complianceStatus"`
	Deleted          bool                    `json:"deleted"`
	ID               string                  `json:"id"`
	IntegrationID    string                  `json:"integrationId"`
	IntegrationType  string                  `json:"integrationType"`
	LastModified     time.Time               `json:"lastModified"`
	Type             string                  `json:"type"`
}

type DeleteResourcesInput struct {
	Resources []DeleteEntry `json:"resources" validate:"min=1,dive"`
}

type DeleteEntry struct {
	ID string `json:"id" validate:"required"`
}

type ListResourcesInput struct {
	// ***** Filtering *****
	// Only include resources with a specific compliance status
	ComplianceStatus models.ComplianceStatus `json:"complianceStatus" validate:"omitempty,oneof=ERROR FAIL PASS"`

	// Only include resources which are or are not deleted
	Deleted *bool `json:"deleted"`

	// Only include resources whose ID contains this substring (case-insensitive)
	IDContains string `json:"idContains"`

	// Only include resources from this source integration
	IntegrationID string `json:"integrationId" validate:"omitempty,uuid4"`

	// Only include resoures from this integration type
	IntegrationType string `json:"integrationType" validate:"omitempty,oneof=aws"`

	// Only include resources which match one of these resource types
	Types []string `json:"types" validate:"omitempty,dive,required"`

	// ***** Projection *****
	// Resource fields to select (default: all except attributes)
	Fields []string `json:"fields" validate:"omitempty,dive,required"`

	// ***** Sorting *****
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=complianceStatus id lastModified type"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ***** Paging *****
	PageSize int `json:"pageSize" validate:"omitempty,min=1"`
	Page     int `json:"page" validate:"omitempty,min=1"`
}

type ListResourcesOutput struct {
	Paging    Paging     `json:"paging"`
	Resources []Resource `json:"resources"`
}

type Paging struct {
	ThisPage   int `json:"thisPage"`
	TotalPages int `json:"totalPages"`
	TotalItems int `json:"totalItems"`
}
