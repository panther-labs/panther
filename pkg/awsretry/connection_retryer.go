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

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/request"
)

func NewConnectionErrRetryer(maxRetries int) *ConnectionErrRetryer {
	return &ConnectionErrRetryer{
		DefaultRetryer: client.DefaultRetryer{
			NumMaxRetries: maxRetries, // MUST be set or all retrying is skipped!
		},
	}
}

// ConnectionErrRetryer wraps the SDK's built in DefaultRetryer adding customization
// to retry `connection reset by peer` errors.
// Not that this retryer should be used for either idempotent operations, or for operations
// where performing duplicate requests to AWS is acceptable.
// See also: https://github.com/aws/aws-sdk-go/issues/3027#issuecomment-567269161
type ConnectionErrRetryer struct {
	client.DefaultRetryer
}

func (r ConnectionErrRetryer) ShouldRetry(req *request.Request) bool {
	if req.Error != nil {
		if strings.Contains(req.Error.Error(), "connection reset by peer") {
			return true
		}
	}

	// Fallback to SDK's built in retry rules
	return r.DefaultRetryer.ShouldRetry(req)
}
