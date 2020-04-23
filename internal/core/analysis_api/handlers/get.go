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
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aws/aws-lambda-go/events"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type getParams struct {
	ID        models.ID
	VersionID models.VersionID
}

// GetPolicy retrieves a policy from Dynamo or S3.
func GetPolicy(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return handleGet(request, typePolicy)
}

// GetRule retrieves a rule from Dynamo or S3.
func GetRule(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return handleGet(request, typeRule)
}

// GetRule retrieves a rule from Dynamo or S3.
func GetGlobal(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return handleGet(request, typeGlobal)
}

// Handle GET request for GetPolicy, GetRule, and GetGlobal
func handleGet(request *events.APIGatewayProxyRequest, codeType string) *events.APIGatewayProxyResponse {
	input, err := parseGet(request, codeType)
	if err != nil {
		return badRequest(err)
	}

	var item *tableItem
	if input.VersionID == "" {
		// Get latest version from Dynamo
		item, err = dynamoGet(input.ID, false)
	} else {
		// Get specific version from S3
		item, err = s3Get(input.ID, input.VersionID)
	}

	if err != nil {
		return failedRequest(fmt.Sprintf("Internal error finding %s (%s)", input.ID, codeType), http.StatusInternalServerError)
	}
	if item == nil {
		return failedRequest(fmt.Sprintf("Cannot find %s (%s)", input.ID, codeType), http.StatusNotFound)
	}

	if item.Type != codeType {
		// Item is the wrong type (e.g. a policy, not a rule)
		return failedRequest(fmt.Sprintf("Cannot find %s (%s)", input.ID, codeType), http.StatusNotFound)
	}

	// Add current pass/fail information and convert to external Policy model
	if codeType == typePolicy {
		status, err := getComplianceStatus(input.ID)
		if err != nil {
			return failedRequest(fmt.Sprintf("Internal error finding %s (%s)", input.ID, codeType), http.StatusInternalServerError)
		}
		return gatewayapi.MarshalResponse(item.Policy(status.Status), http.StatusOK)
	}
	if codeType == typeRule {
		return gatewayapi.MarshalResponse(item.Rule(), http.StatusOK)
	}
	return gatewayapi.MarshalResponse(item.Global(), http.StatusOK)
}

// Parse GET parameters for GetPolicy and GetRule
func parseGet(request *events.APIGatewayProxyRequest, codeType string) (*getParams, error) {
	params := &getParams{
		VersionID: models.VersionID(request.QueryStringParameters["versionId"]),
	}

	idKey := "policyId"
	if codeType == typeRule {
		idKey = "ruleId"
	} else if codeType == typeGlobal {
		idKey = "globalId"
	}
	id, err := url.QueryUnescape(request.QueryStringParameters[idKey])
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %s", idKey, err)
	}
	params.ID = models.ID(id)

	if err := params.ID.Validate(nil); err != nil {
		return nil, fmt.Errorf("invalid %s: %s", idKey, err)
	}

	if params.VersionID != "" {
		if err := params.VersionID.Validate(nil); err != nil {
			return nil, errors.New("invalid versionId: " + err.Error())
		}
	}

	return params, nil
}
