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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	defaultDedupPeriodMinutes = 60
)

// CreateRule adds a new rule to the Dynamo table.
func CreateRule(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseUpdateRule(request)
	if err != nil {
		return badRequest(err)
	}

	item := &tableItem{
		Body:               input.Body,
		DedupPeriodMinutes: input.DedupPeriodMinutes,
		Description:        input.Description,
		DisplayName:        input.DisplayName,
		Enabled:            input.Enabled,
		ID:                 input.ID,
		OutputIds:          input.OutputIds,
		Reference:          input.Reference,
		ResourceTypes:      input.LogTypes,
		Runbook:            input.Runbook,
		Severity:           input.Severity,
		Tags:               input.Tags,
		Tests:              input.Tests,
		Type:               typeRule,
	}

	if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
		if err == errExists {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusConflict}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(item.Rule(), http.StatusCreated)
}

// body parsing shared by CreateRule and ModifyRule
func parseUpdateRule(request *events.APIGatewayProxyRequest) (*models.UpdateRule, error) {
	var result models.UpdateRule
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	// in case it is not set, put a default. Minimum value for DedupPeriodMinutes is 15, so 0 means it's not set
	if result.DedupPeriodMinutes == 0 {
		result.DedupPeriodMinutes = defaultDedupPeriodMinutes
	}

	if err := result.Validate(nil); err != nil {
		return nil, err
	}

	// Rule names are embedded in emails, alert outputs, etc. Prevent a possible injection attack
	if genericapi.ContainsHTML(string(result.DisplayName)) {
		return nil, fmt.Errorf("display name: %v", genericapi.ErrContainsHTML)
	}

	return &result, nil
}
