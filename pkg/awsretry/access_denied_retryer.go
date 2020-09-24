package awsretry

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
	"strings"

	"github.com/aws/aws-sdk-go/aws/request"
)

func NewAccessDeniedRetryer(maxRetries int) *AccessDeniedRetryer {
	return &AccessDeniedRetryer{
		ConnectionErrRetryer: NewConnectionErrRetryer(maxRetries),
	}
}

// AccessDeniedRetryer wraps the ConnectionErrRetryer with extra logic that retries AccessDenied exceptions
// TODO: This could be refactored slightly for a more composable type of Retryer where each caller
// can pick different retry strategies depending on their needs
type AccessDeniedRetryer struct {
	*ConnectionErrRetryer
}

func (r AccessDeniedRetryer) ShouldRetry(req *request.Request) bool {
	if req.Error != nil {
		if strings.Contains(req.Error.Error(), "AccessDenied") {
			return true
		}
	}

	// Fallback to ConnectionErr Retryer
	return r.ConnectionErrRetryer.ShouldRetry(req)
}
