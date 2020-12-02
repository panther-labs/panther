package api

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

	"go.uber.org/zap"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// getAlertOutputs - Get output ids for an alert via the specified overrides or the defaults in panther
func getAlertOutputs(alert *deliveryModels.Alert) ([]*outputModels.AlertOutput, error) {
	// fetch available panther outputs
	outputs, err := getOutputs()
	if err != nil {
		return nil, err
	}

	// If alert has neither outputs IDs or dynamic dest. override specified, return the defaults for the severity
	if len(alert.OutputIds) == 0 && alert.DestinationOverride == nil {
		defaultsForSeverity := []*outputModels.AlertOutput{}
		for _, output := range outputs {
			// If `DefaultForSeverity` is nil or empty, this loop will skip
			for _, outputSeverity := range output.DefaultForSeverity {
				if alert.Severity == *outputSeverity {
					defaultsForSeverity = append(defaultsForSeverity, output)
				}
			}
		}
		return defaultsForSeverity, nil
	}

	// If alert has a dynamically set destination override, return the specified output overrides for the alert
	alertOutputs := []*outputModels.AlertOutput{}
	for _, output := range outputs {
		for _, outputID := range alert.DestinationOverride {
			if *output.OutputID == outputID {
				alertOutputs = append(alertOutputs, output)
			}
		}
	}

	if len(alertOutputs) > 0 {
		return alertOutputs, nil
	}

	// Otherwise, return the specified output overrides for the alert
	for _, output := range outputs {
		for _, outputID := range alert.OutputIds {
			if *output.OutputID == outputID {
				alertOutputs = append(alertOutputs, output)
			}
		}
	}
	return alertOutputs, nil
}

// getOutputs - Gets a list of outputs from panther (using a cache)
func getOutputs() ([]*outputModels.AlertOutput, error) {
	if outputsCache.isExpired() {
		outputs, err := fetchOutputs()
		if err != nil {
			return nil, err
		}
		outputsCache.setOutputs(outputs)
		outputsCache.setExpiry(time.Now().UTC())
	}
	return outputsCache.getOutputs(), nil
}

// fetchOutputs - performs an API query to get a list of outputs
func fetchOutputs() ([]*outputModels.AlertOutput, error) {
	zap.L().Debug("getting default outputs")
	input := outputModels.LambdaInput{GetOutputsWithSecrets: &outputModels.GetOutputsWithSecretsInput{}}
	outputs := outputModels.GetOutputsOutput{}
	if err := genericapi.Invoke(lambdaClient, env.OutputsAPI, &input, &outputs); err != nil {
		return nil, err
	}
	return outputs, nil
}
