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
	"encoding/hex"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
)

// GetEvent retrieves a specific event
func (API) GetEvent(input *models.GetEventInput) (output *models.GetEventOutput, err error) {
	operation := common.OpLogManager.Start("getEvent")
	defer func() {
		operation.Stop()
		operation.Log(err)
	}()

	binaryEventID, err := hex.DecodeString(*input.EventID)
	if err != nil {
		err = errors.Wrap(err, "failed to decode: "+*input.EventID)
		return nil, err
	}
	event, err := alertsDB.GetEvent(binaryEventID)
	if err != nil {
		return nil, err
	}

	return &models.GetEventOutput{
		Event: event,
	}, nil
}
