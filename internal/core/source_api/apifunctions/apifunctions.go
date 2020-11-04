package apifunctions

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

	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/api"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Below are function call entry points to the api that allow callers easily use the lambda interface.
// There are no referenced external packages (other than `models`) to minimize pulling in unneeded code.

// ListLogTypes gets the current set of logTypes in use
func ListLogTypes(_ context.Context, lambdaClient lambdaiface.LambdaAPI) ([]string, error) {
	var listLogTypesOutput models.ListLogTypesOutput
	var listLogTypesInput = &models.LambdaInput{
		ListLogTypes: &models.ListLogTypesInput{},
	}
	// FIXME: extend genericapi to use context
	if err := genericapi.Invoke(lambdaClient, api.LambdaName, listLogTypesInput, &listLogTypesOutput); err != nil {
		return nil, errors.Wrap(err, "error calling source-api to list logTypes")
	}

	return listLogTypesOutput.LogTypes, nil
}
