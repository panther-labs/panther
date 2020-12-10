package forwarder

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

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	mappingAgeOut         = 2 * time.Minute
	sourceAPIFunctionName = "panther-source-api"
)

// Returns the label for an integration
// It will return an empty string if the integration doesn't exist
func (sh *StreamHandler) getIntegrationLabel(integrationID string) (string, error) {
	if sh.integrationIDCache == nil {
		sh.integrationIDCache = make(map[string]string)
	}
	if time.Since(sh.lastUpdatedCache) > mappingAgeOut {
		if err := sh.updateIntegrationMapping(); err != nil {
			return "", err
		}
	}
	return sh.integrationIDCache[integrationID], nil
}

func (sh *StreamHandler) updateIntegrationMapping() error {
	input := &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{
			IntegrationType: aws.String(models.IntegrationTypeAWSScan),
		},
	}
	var output []*models.SourceIntegration
	if err := genericapi.Invoke(sh.LambdaClient, sourceAPIFunctionName, input, &output); err != nil {
		return err
	}

	// Reset the cache
	sh.integrationIDCache = make(map[string]string)
	for _, integration := range output {
		sh.integrationIDCache[integration.IntegrationID] = integration.IntegrationLabel
	}
	sh.lastUpdatedCache = time.Now()
	return nil
}
