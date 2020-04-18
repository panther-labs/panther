package api

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
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsathena"
)

func (api API) StopQuery(input *models.StopQueryInput) (*models.StopQueryOutput, error) {
	var output models.StopQueryOutput

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}

		// allows tracing queries
		zap.L().Info("StopQuery",
			zap.String("queryId", input.QueryID),
			zap.Error(err))
	}()

	_, err = awsathena.StopQuery(athenaClient, input.QueryID)
	if err != nil {
		return &output, err
	}

	return api.GetQueryStatus(input)
}
