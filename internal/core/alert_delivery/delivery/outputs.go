package delivery

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
	"os"
	"time"

	"go.uber.org/zap"

	alertmodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Global variables
var (
	outputsAPI = os.Getenv("OUTPUTS_API")
)

// fetchOutputs - performs an API query to get a list of outputs
func fetchOutputs() ([]*outputmodels.AlertOutput, error) {
	zap.L().Debug("getting default outputs")
	input := outputmodels.LambdaInput{GetOutputsWithSecrets: &outputmodels.GetOutputsWithSecretsInput{}}
	var outputs outputmodels.GetOutputsOutput
	if err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &outputs); err != nil {
		return nil, err
	}
	return outputs, nil
}

// getOutputs - Gets a list of outputs from panther
func getOutputs() ([]*outputmodels.AlertOutput, error) {
	if cache.get() == nil || cache.isExpired() {
		outputs, err := fetchOutputs()
		if err != nil {
			return nil, err
		}
		cache.setOutputs(outputs)
		cache.setExpiry(time.Now().UTC())
		return cache.getOutputs(), nil
	}
	return cache.getOutputs(), nil
}

// getAlertOutputs - Get output ids for an alert
func getAlertOutputs(alert *alertmodels.Alert) ([]*outputmodels.AlertOutput, error) {
	outputIds, err := getOutputs()
	if err != nil {
		return nil, err
	}

	// If alert doesn't have outputs IDs specified, return the defaults for the severity
	if len(alert.OutputIds) == 0 {
		return getOutputsBySeverity(alert.Severity), nil
	}

	result := []*outputmodels.AlertOutput{}
	for _, output := range outputIds {
		for _, alertOutputID := range alert.OutputIds {
			if *output.OutputID == alertOutputID {
				result = append(result, output)
			}
		}
	}
	return result, nil
}

func getOutputsBySeverity(severity string) []*outputmodels.AlertOutput {
	result := []*outputmodels.AlertOutput{}
	if cache.get() == nil {
		return result
	}

	for _, output := range cache.getOutputs() {
		for _, outputSeverity := range output.DefaultForSeverity {
			if severity == *outputSeverity {
				result = append(result, output)
			}
		}
	}
	return result
}
