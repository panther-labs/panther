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
	"os"
	"time"

	"go.uber.org/zap"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Global variables
var (
	outputsAPI = os.Getenv("OUTPUTS_API")
)

// fetchOutputs - performs an API query to get a list of outputs
func fetchOutputs() ([]*outputModels.AlertOutput, error) {
	zap.L().Debug("getting default outputs")
	input := outputModels.LambdaInput{GetOutputsWithSecrets: &outputModels.GetOutputsWithSecretsInput{}}
	var outputs outputModels.GetOutputsOutput
	if err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &outputs); err != nil {
		return nil, err
	}
	return outputs, nil
}

// GetOutputs - Gets a list of outputs from panther
func GetOutputs() ([]*outputModels.AlertOutput, error) {
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

// GetAlertOutputs - Get output ids for an alert
func GetAlertOutputs(alert *deliveryModels.Alert) ([]*outputModels.AlertOutput, error) {
	outputIds, err := GetOutputs()
	if err != nil {
		return nil, err
	}

	// If alert doesn't have outputs IDs specified, return the defaults for the severity
	if len(alert.OutputIds) == 0 {
		return getOutputsBySeverity(alert.Severity), nil
	}

	result := []*outputModels.AlertOutput{}
	for _, output := range outputIds {
		for _, alertOutputID := range alert.OutputIds {
			if *output.OutputID == alertOutputID {
				result = append(result, output)
			}
		}
	}
	return result, nil
}

func getOutputsBySeverity(severity string) []*outputModels.AlertOutput {
	result := []*outputModels.AlertOutput{}
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
