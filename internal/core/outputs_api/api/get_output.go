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
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

// GetOutput retrieves a single alert output
func (API) GetOutput(input *models.GetOutputInput) (*models.GetOutputOutput, error) {
	item, err := outputsTable.GetOutput(input.OutputID)
	if err != nil {
		return nil, err
	}

	alertOutput, err := ItemToAlertOutput(item)
	if err != nil {
		return nil, err
	}

	if err = checkAndUpdateVerificationStatus(alertOutput); err != nil {
		return nil, err
	}

	return alertOutput, nil
}

// Checks if an Alert Output is marked as verified or not.
// If the Alert Output is not marked as verified, we check the state of the
// configuration processes and update as appropriate
func checkAndUpdateVerificationStatus(output *models.AlertOutput) error {
	if *output.VerificationStatus == models.VerificationStatusSuccess {
		return nil
	}

	zap.L().Info("update the verification status of output",
		zap.String("outputId", *output.OutputID))
	newStatus, err := outputVerification.GetVerificationStatus(output)
	if err != nil {
		return err
	}
	if *newStatus != *output.VerificationStatus {
		zap.L().Info("verification status of output has changed",
			zap.String("oldVerificationStatus", *output.VerificationStatus),
			zap.String("newVerificationStatus", *newStatus))
		output.VerificationStatus = newStatus
		outputItem, err := AlertOutputToItem(output)
		if err != nil {
			return err
		}
		_, err = outputsTable.UpdateOutput(outputItem)
		if err != nil {
			return nil
		}
	}
	return nil
}
