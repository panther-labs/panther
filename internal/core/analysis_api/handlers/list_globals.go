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
	"net/http"
	"sort"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// ListGlobals pages through globals from a single organization.
func (API) ListGlobals(input *models.ListGlobalsInput) *events.APIGatewayProxyResponse {
	var err error

	// Parse the input
	ascending := defaultSortAscending
	if sortDir := request.QueryStringParameters["sortDir"]; sortDir != "" {
		ascending = sortDir == "ascending"
	}

	page := defaultPage
	if requestPage := request.QueryStringParameters["page"]; requestPage != "" {
		page, err = strconv.Atoi(requestPage)
		if err != nil {
			zap.L().Error("unable to parse page query parameter", zap.String("page", requestPage))
			return badRequest(errors.New("invalid page: " + err.Error()))
		}
	}

	pageSize := defaultPageSize
	if requestPageSize := request.QueryStringParameters["pageSize"]; requestPageSize != "" {
		pageSize, err = strconv.Atoi(requestPageSize)
		if err != nil {
			zap.L().Error("unable to parse pageSize query parameter", zap.String("pageSize", requestPageSize))
			return badRequest(errors.New("invalid page: " + err.Error()))
		}
	}

	// Build the dynamodb scan expression
	projection := expression.NamesList(
		// only fields needed for frontend global list
		expression.Name("id"),
		expression.Name("lastModified"),
		expression.Name("tags"),
	)
	filter := expression.Equal(expression.Name("type"), expression.Value(typeGlobal))

	expr, err := expression.NewBuilder().
		WithFilter(filter).
		WithProjection(projection).
		Build()

	if err != nil {
		zap.L().Error("unable to build dynamodb scan expression", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	scanInput := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &env.Table,
	}

	// Scan dynamo
	var globals []*models.GlobalSummary
	err = scanPages(scanInput, func(item *tableItem) error {
		globals = append(globals, &models.GlobalSummary{
			ID:           item.ID,
			LastModified: item.LastModified,
			Tags:         item.Tags,
		})
		return nil
	})

	if err != nil {
		zap.L().Error("failed to scan globals", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Handle the 0 globals case
	if len(globals) == 0 {
		paging := &models.Paging{
			ThisPage:   aws.Int64(0),
			TotalItems: aws.Int64(0),
			TotalPages: aws.Int64(0),
		}
		return gatewayapi.MarshalResponse(
			&models.GlobalList{Paging: paging, Globals: []*models.GlobalSummary{}}, http.StatusOK)
	}

	// Sort the globals
	sort.Slice(globals, func(i, j int) bool {
		left, right := globals[i], globals[j]
		if ascending {
			return left.ID < right.ID
		}
		return left.ID > right.ID
	})

	// Page the globals
	totalPages := len(globals) / pageSize
	if len(globals)%pageSize > 0 {
		totalPages++ // Add one more to page count if there is an incomplete page at the end
	}

	paging := &models.Paging{
		ThisPage:   aws.Int64(int64(page)),
		TotalItems: aws.Int64(int64(len(globals))),
		TotalPages: aws.Int64(int64(totalPages)),
	}

	// Truncate globals to just the requested page
	lowerBound := intMin((page-1)*pageSize, len(globals))
	upperBound := intMin(page*pageSize, len(globals))

	return gatewayapi.MarshalResponse(&models.GlobalList{Paging: paging, Globals: globals[lowerBound:upperBound]}, http.StatusOK)
}
