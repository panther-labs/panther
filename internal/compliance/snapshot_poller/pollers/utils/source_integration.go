package utils

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
	"go.uber.org/zap"
	"regexp"
	"time"
)

const sourceAPIFunctionName = "panther-source-api"

// Cached source integration
type cachedIntegration struct {
	sourceIntegration models.SourceIntegration
	Timestamp         time.Time
}

// Source integration cache with a TTL of a minute
var (
	integrationCache                       = make(map[string]cachedIntegration)
	sess                                   = session.Must(session.NewSession())
	lambdaClient     lambdaiface.LambdaAPI = lambda.New(sess)
)

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
	if err := genericapi.Invoke(lambdaClient, sourceAPIFunctionName, input, &output); err != nil {
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

func matchRegexFilter(regexFilter *string, resourceARN string) (matched bool, err error) {
	if regexFilter == nil || *regexFilter == "" {
		return false, nil
	}
	regexFilterCompiled, err := regexp.Compile(*regexFilter)
	if err != nil {
		zap.L().Error("failed to compile regex filter", zap.Error(err),
			zap.String("filter regex", *regexFilter))
		return false, err
	}
	if regexFilterCompiled.MatchString(resourceARN) {
		zap.L().Info("regex filter matched - skipping single resource scan",
			zap.String("regex filter", *regexFilter), zap.String("resource id", resourceARN))
		return true, nil
	}
	return false, nil
}
