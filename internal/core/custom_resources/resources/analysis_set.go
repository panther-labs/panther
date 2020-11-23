package resources

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
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"go.uber.org/zap"

	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type AnalysisSetProperties struct {
	PackURLs []string
}

func customAnalysisSet(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const resourceID = "custom:analysis:init"

	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props AnalysisSetProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		// Check if rules/policies already exist - never overwrite existing items.
		// It's easier and faster to just scan the dynamo table directly instead of going through
		// the analysis-api. This way, we can stop immediately if an entry is found.
		response, err := dynamoClient.Scan(&dynamodb.ScanInput{
			Limit:     aws.Int64(1),
			TableName: aws.String("panther-analysis"),
		})
		if err != nil {
			// Errors are logged but not returned - we do not need to fail the entire deployment
			// because the user can always manually BulkUpload the python analysis set later.
			zap.L().Error("failed to scan panther-analysis table", zap.Error(err))
			return resourceID, nil, nil
		}

		if len(response.Items) > 0 {
			zap.L().Info("skipping create/update because the panther-analysis table already has items")
			return resourceID, nil, nil
		}

		if err := initializeAnalysisSets(props.PackURLs); err != nil {
			zap.L().Error("failed to bulk upload python analysis set", zap.Error(err))
		}
		return resourceID, nil, nil

	default:
		// ignore deletes
		return event.PhysicalResourceID, nil, nil
	}
}

// Install Python rules/policies for a fresh deployment.
func initializeAnalysisSets(sets []string) error {
	apiClient := gatewayapi.NewClient(lambdaClient, "panther-analysis-api")

	var newRules, newPolicies int
	for _, url := range sets {
		url = strings.TrimSpace(url)
		if url == "" {
			// blank strings can wind up here when commenting out sections of the config file
			zap.L().Warn("skipping blank analysis set url")
			continue
		}

		zap.L().Info("downloading analysis pack", zap.String("url", url))
		contents, err := download(url)
		if err != nil {
			return err
		}

		zap.L().Info("BulkUpload analysis pack to analysis-api", zap.String("url", url))
		encoded := base64.StdEncoding.EncodeToString(contents)

		input := analysismodels.LambdaInput{
			BulkUpload: &analysismodels.BulkUploadInput{
				Data:   encoded,
				UserID: systemUserID,
			},
		}
		var response analysismodels.BulkUploadOutput
		if _, err := apiClient.Invoke(&input, &response); err != nil {
			return fmt.Errorf("failed to upload %s: %v", url, err)
		}

		newRules += response.NewRules
		newPolicies += response.NewPolicies
	}

	zap.L().Info("successfully initialized analysis sets",
		zap.Strings("sets", sets), zap.Int("newRules", newRules),
		zap.Int("newPolicies", newPolicies))
	return nil
}

// Download a file in memory.
func download(url string) ([]byte, error) {
	response, err := http.Get(url) // nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to GET %s: %v", url, err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %v", url, err)
	}

	return body, nil
}
