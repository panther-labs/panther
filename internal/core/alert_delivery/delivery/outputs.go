package delivery

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type outputCacheKey struct {
	OutputID string
}

type cachedOutput struct {
	Output    *outputmodels.AlertOutput
	Timestamp time.Time
}

type cachedOutputIDs struct {
	//Map from Severity -> List of output Ids
	Outputs   map[string][]*string
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
	alertOutputCache      = make(map[outputCacheKey]cachedOutput) // Map outputID to its credentials
	defaultOutputIDsCache *cachedOutputIDs                        // Map of organizationId to default output ids
	outputsAPI            = os.Getenv("OUTPUTS_API")
	refreshInterval       = getRefreshInterval()
)

// Get output ids for an alert
func getAlertOutputIds(alert *alertmodels.Alert) ([]*string, error) {
	if len(alert.OutputIDs) > 0 {
		return alert.OutputIDs, nil
	}

	if defaultOutputIDsCache != nil && time.Since(defaultOutputIDsCache.Timestamp) < refreshInterval {
		zap.L().Info("using cached output Ids")
		return defaultOutputIDsCache.Outputs[*alert.Severity], nil
	}

	zap.L().Info("getting default outputs")
	input := outputmodels.LambdaInput{GetDefaultOutputs: &outputmodels.GetDefaultOutputsInput{}}
	var defaultOutputs outputmodels.GetDefaultOutputsOutput
	if err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &defaultOutputs); err != nil {
		return nil, err
	}

	defaultOutputIDsCache = &cachedOutputIDs{
		Timestamp: time.Now(),
		Outputs:   make(map[string][]*string, len(defaultOutputs.Defaults)),
	}

	for _, output := range defaultOutputs.Defaults {
		defaultOutputIDsCache.Outputs[*output.Severity] = output.OutputIDs
	}

	zap.L().Debug("default output ids cache", zap.Any("cache", defaultOutputIDsCache))
	return defaultOutputIDsCache.Outputs[*alert.Severity], nil
}

// Get output details, either from in-memory cache or the outputs-api
func getOutput(outputID string) (*outputmodels.GetOutputOutput, error) {
	key := outputCacheKey{OutputID: outputID}

	if cached, ok := alertOutputCache[key]; ok && time.Since(cached.Timestamp) < refreshInterval {
		zap.L().Info("using cached outputs",
			zap.String("outputID", outputID))
		return cached.Output, nil
	}

	zap.L().Info("getting outputs from outputs-api",
		zap.String("outputID", outputID))

	input := outputmodels.LambdaInput{GetOutput: &outputmodels.GetOutputInput{OutputID: aws.String(outputID)}}
	var result outputmodels.GetOutputOutput
	if err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &result); err != nil {
		return nil, err
	}

	alertOutputCache[key] = cachedOutput{Output: &result, Timestamp: time.Now()}
	return &result, nil
}
