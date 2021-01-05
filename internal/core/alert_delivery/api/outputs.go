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
	"sort"
	"time"

	"go.uber.org/zap"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const alertOutputSkip = "SKIP"

// getAlertOutputs - Get output ids for an alert by dynmaic destinations, destination overrides, or default severity
func getAlertOutputs(alert *deliveryModels.Alert) ([]*outputModels.AlertOutput, error) {
	// fetch available panther outputs
	outputs, err := getOutputs()
	if err != nil {
		return nil, err
	}

	alertOutputs := []*outputModels.AlertOutput{}

	// First, check if we have an override to SKIP dispatching this alert
	if shouldSkip(alert) {
		return alertOutputs, nil
	}

	// Next, prioritize dynamic destinations (set in the detection's python body)
	if alertOutputs, ok := getDynamicDestinations(alert, outputs); ok {
		return alertOutputs, nil
	}

	// Then, destination overrides (set in the detection's form)
	if alertOutputs, ok := getDestinationOverrides(alert, outputs); ok {
		return alertOutputs, nil
	}

	// Finally, the use the severity rating (default)
	return getDefaultOutputs(alert, outputs), nil
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

func shouldSkip(alert *deliveryModels.Alert) bool {
	for _, outputID := range alert.OutputIds {
		if outputID == alertOutputSkip {
			return true
		}
	}
	return false
}

func getDynamicDestinations(alert *deliveryModels.Alert, outputs []*outputModels.AlertOutput) ([]*outputModels.AlertOutput, bool) {
	alertOutputs := []*outputModels.AlertOutput{}
	if len(alert.Destinations) == 0 {
		return alertOutputs, false
	}

	for _, output := range outputs {
		for _, outputID := range alert.Destinations {
			if *output.OutputID == outputID {
				alertOutputs = append(alertOutputs, output)
			}
		}
	}

	return alertOutputs, len(alertOutputs) > 0
}

func getDestinationOverrides(alert *deliveryModels.Alert, outputs []*outputModels.AlertOutput) ([]*outputModels.AlertOutput, bool) {
	alertOutputs := []*outputModels.AlertOutput{}
	if len(alert.OutputIds) == 0 {
		return alertOutputs, false
	}

	for _, output := range outputs {
		for _, outputID := range alert.OutputIds {
			if *output.OutputID == outputID {
				alertOutputs = append(alertOutputs, output)
			}
		}
	}

	return alertOutputs, len(alertOutputs) > 0
}

func getDefaultOutputs(alert *deliveryModels.Alert, outputs []*outputModels.AlertOutput) []*outputModels.AlertOutput {
	alertOutputs := []*outputModels.AlertOutput{}
	for _, output := range outputs {
		for _, outputSeverity := range output.DefaultForSeverity {
			if alert.Severity == *outputSeverity {
				alertOutputs = append(alertOutputs, output)
			}
		}
	}
	return alertOutputs
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

// getUniqueOutputs - Get a list of unique output entries
func getUniqueOutputs(outputs []*outputModels.AlertOutput) []*outputModels.AlertOutput {
	uniqMap := make(map[string]*outputModels.AlertOutput)
	for _, output := range outputs {
		uniqMap[*output.OutputID] = output
	}

	// turn the map keys into a slice
	uniqSlice := make([]*outputModels.AlertOutput, 0, len(uniqMap))
	for _, output := range uniqMap {
		uniqSlice = append(uniqSlice, output)
	}
	// Sort by OutputID string. This is not functionally necessary, but it makes
	// testing easier and the overhead is relatively small.
	sort.Slice(uniqSlice, func(i, j int) bool {
		return *(uniqSlice[i]).OutputID < *(uniqSlice[j]).OutputID
	})
	return uniqSlice
}
