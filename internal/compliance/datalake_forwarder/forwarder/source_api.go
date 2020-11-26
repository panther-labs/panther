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
	"errors"
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
	mappingAgeOut         = time.Minute * 5
	sourceAPIFunctionName = "panther-source-api"
)

func (sh *StreamHandler) getIntegrationLabel(integrationID string) (string, error) {
	label, ok := integrationIDMappings[integrationID]
	if !ok || time.Since(lastUpdated) > mappingAgeOut {
		err := sh.updateIntegrationMapping()
		if err != nil {
			return "", err
		}
		label, ok = integrationIDMappings[integrationID]
		if !ok {
			return "", errors.New("unable to map integrationId " + integrationID + " to an integrationLabel")
		}
	}
	return label, nil
}

func (sh StreamHandler) updateIntegrationMapping() error {
	input := &sourceAPIModels.LambdaInput{
		ListIntegrations: &sourceAPIModels.ListIntegrationsInput{
			IntegrationType: aws.String(sourceAPIModels.IntegrationTypeAWSScan),
		},
	}
	var output []*sourceAPIModels.SourceIntegration
	if err := genericapi.Invoke(sh.lambdaClient, sourceAPIFunctionName, input, &output); err != nil {
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
