package utils

import (
	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/genericapi"
	"go.uber.org/zap"
	"time"
)

const sourceAPIFunctionName = "panther-source-api"

// Cached source integration
type cachedIntegration struct {
	sourceIntegration models.SourceIntegration
	Timestamp         time.Time
}

// Source integration cache with a TTL of a minute
var integrationCache = make(map[string]cachedIntegration)

// TODO: If this takes a huge performance hit, update source-api to allow getting a single integration
func GetIntegration(integrationID string) (integration *models.SourceIntegration, err error) {
	// Return the cached short-lived integration
	if cachedIntegration, exists := integrationCache[integrationID]; exists {
		if time.Now().Add(-1 * time.Minute).Before(cachedIntegration.Timestamp) {
			zap.L().Debug("integration was cached", zap.Any("integration id", integrationID))
			return &cachedIntegration.sourceIntegration, nil
		}
		zap.L().Debug("integration cache expired", zap.Any("integration id", integrationID))
	}

	// Retrieve integrations to update the cache
	input := &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{},
	}
	var output []*models.SourceIntegration
	if err := genericapi.Invoke(common.LambdaClient, sourceAPIFunctionName, input, &output); err != nil {
		zap.L().Warn("encountered an issue when trying to list integrations from source-api", zap.Error(err))
		return nil, err
	}

	// Cache and return integration
	var result *models.SourceIntegration
	for _, integration := range output {
		integrationCache[integration.IntegrationID] = cachedIntegration{
			sourceIntegration: *integration,
			Timestamp:         time.Now(),
		}
		if integrationID == integration.IntegrationID {
			result = integration
		}
	}

	if result == nil {
		zap.L().Warn("target integration id not found", zap.String("target integration id", integrationID))
	}
	return result, nil
}
