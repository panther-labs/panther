package api

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
	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsathena"
)

// FIXME: consider adding as stand-alone lambda to de-couple this from Athena api

func (API) NotifyAppSync(input *models.NotifyAppSyncInput) (*models.NotifyAppSyncOutput, error) {
	output := &models.NotifyAppSyncOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	executionStatus, err := awsathena.Status(athenaClient, input.QueryID)
	if err != nil {
		return output, err
	}
	output.Status = getQueryStatus(executionStatus)

	// make https request to appsync endpoint notifying query is complete, sending  queryId and status
	// FIXME: add call back

	return output, nil
}
