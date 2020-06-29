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

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type outputsCache struct {
	// All cached outputs
	Outputs   []*outputmodels.AlertOutput
	Timestamp time.Time
}

func getRefreshInterval() time.Duration {
	intervalMins := os.Getenv("OUTPUTS_REFRESH_INTERVAL_MIN")
	if intervalMins == "" {
		intervalMins = "5"
	}
	return time.Duration(mustParseInt(intervalMins)) * time.Minute
}

var (
	cache           *outputsCache
	outputsAPI      = os.Getenv("OUTPUTS_API")
	refreshInterval = getRefreshInterval()
)

// Get output ids for an alert
func getAlertOutputs(alert *alertmodels.Alert) ([]*outputmodels.AlertOutput, error) {
	if cache == nil || time.Since(cache.Timestamp) > refreshInterval {
		zap.L().Debug("getting cached default outputs")
		input := outputmodels.LambdaInput{GetOutputsWithSecrets: &outputmodels.GetOutputsWithSecretsInput{}}
		var outputs outputmodels.GetOutputsOutput
		if err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &outputs); err != nil {
			return nil, err
		}
		cache = &outputsCache{
			Outputs:   outputs,
			Timestamp: time.Now().UTC(),
		}
	}

	// If alert doesn't have outputs IDs specified, return the defaults for the severity
	if len(alert.OutputIDs) == 0 {
		return getOutputsBySeverity(alert.Severity), nil
	}

	result := []*outputmodels.AlertOutput{}
	for _, output := range cache.Outputs {
		for _, alertOutputID := range alert.OutputIDs {
			if *output.OutputID == alertOutputID {
				result = append(result, output)
			}
		}
	}
	return result, nil
}

func getOutputsBySeverity(severity string) []*outputmodels.AlertOutput {
	result := []*outputmodels.AlertOutput{}
	if cache == nil {
		return result
	}

	for _, output := range cache.Outputs {
		for _, outputSeverity := range output.DefaultForSeverity {
			if severity == *outputSeverity {
				result = append(result, output)
			}
		}
	}
	return result
}
