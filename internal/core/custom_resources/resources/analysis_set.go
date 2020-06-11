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
	"time"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/lambda"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type AnalysisSetProperties struct {
	AnalysisAPIEndpoint string `validate:"required"`
	PackURLs            []string
}

func customAnalysisSet(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate:
		var props AnalysisSetProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		httpClient := gatewayapi.GatewayClient(awsSession)
		apiClient := client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
			WithBasePath("/v1").WithHost(props.AnalysisAPIEndpoint))

		// The policy-engine and rules-engine must exist so the analysis-api can update their global layer.
		// Waiting here is easier than using a CloudFormation dependency because of our stack structure.
		// Typically this won't take more than a few seconds.
		if err := waitForPythonEngines(); err != nil {
			return "", nil, err
		}
		return "custom:analysis:init", nil, initializeAnalysisSets(props.PackURLs, apiClient, httpClient)

	default:
		// ignore deletes and updates - we do not want to modify an existing ruleset from here.
		return event.PhysicalResourceID, nil, nil
	}
}

func waitForPythonEngines() error {
	zap.L().Info("waiting for policy-engine and rules-engine to exist")
	const timeout = 5 * time.Minute

	for start := time.Now(); time.Since(start) < timeout; time.Sleep(5 * time.Second) {
		exists, err := lambdaFunctionExists("panther-policy-engine")
		if err != nil {
			return err
		}
		if !exists {
			continue
		}

		exists, err = lambdaFunctionExists("panther-rules-engine")
		if err != nil {
			return err
		}
		if !exists {
			continue
		}

		return nil // both exist
	}

	return fmt.Errorf("timed out waiting for Python engines")
}

func lambdaFunctionExists(name string) (bool, error) {
	_, err := lambdaClient.GetFunction(&lambda.GetFunctionInput{FunctionName: &name})
	if err == nil {
		return true, nil
	}

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == lambda.ErrCodeResourceNotFoundException {
		err = nil
	}
	return false, err
}

// Install Python rules/policies for a fresh deployment.
func initializeAnalysisSets(sets []string, apiClient *client.PantherAnalysis, httpClient *http.Client) error {
	var newRules, newPolicies int64
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
		response, err := apiClient.Operations.BulkUpload(&operations.BulkUploadParams{
			Body: &analysismodels.BulkUpload{
				Data:   analysismodels.Base64zipfile(encoded),
				UserID: systemUserID,
			},
			HTTPClient: httpClient,
		})
		if err != nil {
			return fmt.Errorf("failed to upload %s: %v", url, err)
		}

		newRules += *response.Payload.NewRules
		newPolicies += *response.Payload.NewPolicies
	}

	zap.L().Info("successfully initialized analysis sets",
		zap.Strings("sets", sets), zap.Int64("newRules", newRules),
		zap.Int64("newPolicies", newPolicies))
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
