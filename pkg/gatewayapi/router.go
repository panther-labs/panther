package gatewayapi

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
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/genericapi"
)

// MarshalResponse replaces nil maps + slices and serializes a response model.
//
// response is a pointer to a struct and statusCode is the http status to return
func MarshalResponse(response interface{}, statusCode int) *events.APIGatewayProxyResponse {
	genericapi.ReplaceMapSliceNils(response)
	body, err := jsoniter.MarshalToString(response)
	if err != nil {
		zap.L().Error("failed to marshal response", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	return &events.APIGatewayProxyResponse{Body: body, StatusCode: statusCode}
}
