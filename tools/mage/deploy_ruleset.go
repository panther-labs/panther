package mage

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
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// Install Python rules/policies if they don't already exist.
func initializeAnalysisSets(awsSession *session.Session, endpoint string, config *PantherConfig) error {
	httpClient := gatewayapi.GatewayClient(awsSession)
	apiClient := client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(endpoint))

	policies, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		PageSize:   aws.Int64(1),
		HTTPClient: httpClient,
	})
	if err != nil {
		return err
	}

	rules, err := apiClient.Operations.ListRules(&operations.ListRulesParams{
		PageSize:   aws.Int64(1),
		HTTPClient: httpClient,
	})
	if err != nil {
		return err
	}

	if len(policies.Payload.Policies) > 0 || len(rules.Payload.Rules) > 0 {
		if mg.Verbose() {
			fmt.Println("deploy: initial analysis set ignored: policies and/or rules already exist")
		}

		return nil
	}

	var newRules, newPolicies int64
	for _, path := range config.InitialAnalysisSets {
		fmt.Println("deploy: uploading " + path)
		var contents []byte
		if strings.HasPrefix(path, "file://") {
			contents = readFile(strings.TrimPrefix(path, "file://"))
		} else {
			contents, err = download(path)
			if err != nil {
				return err
			}
		}

		// BulkUpload to panther-analysis-api
		encoded := base64.StdEncoding.EncodeToString(contents)
		response, err := apiClient.Operations.BulkUpload(&operations.BulkUploadParams{
			Body: &models.BulkUpload{
				Data:   models.Base64zipfile(encoded),
				UserID: "00000000-0000-0000-0000-000000000000",
			},
			HTTPClient: httpClient,
		})
		if err != nil {
			return err
		}

		newRules += *response.Payload.NewRules
		newPolicies += *response.Payload.NewPolicies
	}

	fmt.Printf("deploy: added %d policies and %d rules\n", newPolicies, newRules)
	return nil
}
