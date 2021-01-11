package utils

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
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	sourceAPIFunctionName   = "panther-source-api"
	integrationCacheTimeout = -1 * time.Minute
)

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
		if time.Now().Add(integrationCacheTimeout).Before(cachedIntegration.Timestamp) {
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

func MatchRegexIgnoreList(globs []string, resourceARN string) (matched bool, err error) {
	for _, glob := range globs {
		if glob == "" {
			continue
		}
		// First,  escape any regex special characters
		escaped := regexp.QuoteMeta(glob)

		// Wildcards in the original pattern are now escaped literals - convert back
		// NOTE: currently no way for user to specify a glob that would match a literal '*'
		regex := "^" + strings.ReplaceAll(escaped, `\*`, `.*`) + "$"
		matcher, err := regexp.Compile(regex)
		if err != nil {
			// We are building the regex, so it should always be valid
			zap.L().Error("invalid regex",
				zap.String("originalPattern", glob),
				zap.String("transformedRegex", regex),
				zap.Error(err),
			)
			continue
		}
		if matcher.MatchString(resourceARN) {
			return true, nil
		}
	}
	return false, nil
}
