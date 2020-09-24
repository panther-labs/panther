package utils

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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// LogAWSError logs an AWS error to zap in a digestable format.
func LogAWSError(apiCall string, err error) {
	var awsErr awserr.Error
	if errors.As(err, &awsErr) {
		zap.L().Error(
			apiCall,
			zap.String("errorCode", awsErr.Code()),
			zap.String("errorMessage", awsErr.Message()),
			zap.Error(errors.Wrap(err, "AWS API call failed")),
		)
	}
}
