package processor

/**
 * A Cloud-Native SIEM for the Modern Security Team
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
	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/resources/client/operations"
	resourcemodels "github.com/panther-labs/panther/api/gateway/resources/models"
)

// How many resources (with attributes) we can request in a single page.
// The goal is to keep this as high as possible while still keeping the result under 6MB.
const resourcePageSize = 2000

// Get a page of resources from the resources-api
//
// Returns {resourceID: resource}, totalPages, error
func getResources(resourceTypes []string, pageno int64) (resourceMap, int64, error) {
	result := make(resourceMap)

	zap.L().Debug("listing resources from resources-api",
		zap.Int64("pageNo", pageno),
		zap.Int("pageSize", resourcePageSize),
		zap.Strings("resourceTypes", resourceTypes),
	)

	page, err := resourceClient.Operations.ListResources(&operations.ListResourcesParams{
		Deleted:    aws.Bool(false),
		Fields:     []string{"attributes", "id", "integrationId", "integrationType", "type"},
		Page:       &pageno,
		PageSize:   aws.Int64(resourcePageSize),
		Types:      resourceTypes,
		HTTPClient: httpClient,
	})
	if err != nil {
		zap.L().Error("failed to list resources", zap.Error(err))
		return nil, 0, err
	}

	for _, resource := range page.Payload.Resources {
		result[string(resource.ID)] = resource
	}
	return result, *page.Payload.Paging.TotalPages, nil
}

func getResource(resourceID string) (*resourcemodels.Resource, error) {
	zap.L().Debug("getting resource from resources-api",
		zap.String("resourceID", resourceID),
	)

	resource, err := resourceClient.Operations.GetResource(&operations.GetResourceParams{
		ResourceID: resourceID,
		HTTPClient: httpClient,
	})
	if err != nil {
		zap.L().Error("failed to get resource", zap.Error(err), zap.String("resourceID", resourceID))
		return nil, err
	}

	return resource.Payload, nil
}
