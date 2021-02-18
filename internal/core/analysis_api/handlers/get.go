package handlers

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
	"fmt"
	"net/http"
	"net/url"

	"github.com/aws/aws-lambda-go/events"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) GetPolicy(input *models.GetPolicyInput) *events.APIGatewayProxyResponse {
	return handleGet(input.ID, input.VersionID, models.TypePolicy)
}

func (API) GetRule(input *models.GetRuleInput) *events.APIGatewayProxyResponse {
	return handleGet(input.ID, input.VersionID, models.TypeRule)
}

func (API) GetGlobal(input *models.GetGlobalInput) *events.APIGatewayProxyResponse {
	return handleGet(input.ID, input.VersionID, models.TypeGlobal)
}

func (API) GetDataModel(input *models.GetDataModelInput) *events.APIGatewayProxyResponse {
	return handleGet(input.ID, input.VersionID, models.TypeDataModel)
}

func (API) GetPack(input *models.GetPackInput) *events.APIGatewayProxyResponse {
	var item *packTableItem
	item, err := dynamoGetPack(input.ID, false)

	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error finding %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if item == nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot find %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusNotFound,
		}
	}
	return gatewayapi.MarshalResponse(item.Pack(), http.StatusOK)
}

// Handle GET request for GetPolicy, GetRule, and GetGlobal
func handleGet(itemID, versionID string, codeType models.DetectionType) *events.APIGatewayProxyResponse {
	var err error
	itemID, err = url.QueryUnescape(itemID)
	if err != nil {
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusBadRequest}
	}

	var item *tableItem
	if versionID == "" {
		// Get latest version from Dynamo
		item, err = dynamoGet(itemID, false)
	} else {
		// Get specific version from S3
		item, err = s3Get(itemID, versionID)
	}

	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error finding %s (%s)", itemID, codeType),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if item == nil || item.Type != codeType {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot find %s (%s)", itemID, codeType),
			StatusCode: http.StatusNotFound,
		}
	}

	switch codeType {
	case models.TypePolicy:
		status, err := getComplianceStatus(itemID)
		if err != nil {
			return &events.APIGatewayProxyResponse{
				Body:       fmt.Sprintf("Internal error finding %s (%s)", itemID, codeType),
				StatusCode: http.StatusInternalServerError,
			}
		}
		return gatewayapi.MarshalResponse(item.Policy(status.Status), http.StatusOK)

	case models.TypeRule:
		// Backwards compatibility fix
		// Rules that were created before the introduction of Rule Threshold
		// will have a default threshold of '0'. However, the minimum threshold we allow is '1'.
		rule := item.Rule()
		if rule.Threshold == 0 {
			rule.Threshold = defaultRuleThreshold
		}
		return gatewayapi.MarshalResponse(rule, http.StatusOK)

	case models.TypeGlobal:
		return gatewayapi.MarshalResponse(item.Global(), http.StatusOK)

	case models.TypeDataModel:
		return gatewayapi.MarshalResponse(item.DataModel(), http.StatusOK)

	default:
		panic("unexpected codeType " + codeType)
	}
}
