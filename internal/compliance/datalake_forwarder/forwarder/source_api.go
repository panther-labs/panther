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

	sourceAPIModels "github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var (
	integrationIDMappings = map[string]string{}
	lastUpdated           time.Time
)

const (
	mappingAgeOut         = 2 * time.Minute
	sourceAPIFunctionName = "panther-source-api"
)

// Returns the label for an integration
// It will return an empty string if the integration doesn't exist
func (sh *StreamHandler) getIntegrationLabel(integrationID string) (string, error) {
	_, ok := integrationIDMappings[integrationID]
	if !ok || time.Since(lastUpdated) > mappingAgeOut {
		err := sh.updateIntegrationMapping()
		if err != nil {
			return "", err
		}
	}
	return integrationIDMappings[integrationID], nil
}

func (sh StreamHandler) updateIntegrationMapping() error {
	input := &sourceAPIModels.LambdaInput{
		ListIntegrations: &sourceAPIModels.ListIntegrationsInput{
			IntegrationType: aws.String(sourceAPIModels.IntegrationTypeAWSScan),
		},
	}
	var output []*sourceAPIModels.SourceIntegration
	if err := genericapi.Invoke(sh.LambdaClient, sourceAPIFunctionName, input, &output); err != nil {
		return err
	}

	// Reset the cache
	integrationIDMappings = make(map[string]string)
	for _, integration := range output {
		integrationIDMappings[integration.IntegrationID] = integration.IntegrationLabel
	}
	lastUpdated = time.Now()

	return nil
}
