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

// CustomRetryer wraps the SDK's built in DefaultRetryer adding additional
// custom features.
type ConnectionErrRetryer struct {
	client.DefaultRetryer
}

// ShouldRetry overrides the SDK's built in DefaultRetryer adding customization
// to retry `connection reset by peer` and `use of closed network connection` errors
func (r ConnectionErrRetryer) ShouldRetry(req *request.Request) bool {
	if req.Error != nil {
		errMsg := req.Error.Error()
		if strings.Contains(errMsg, "connection reset by peer") {
			return true
		}
		if strings.Contains(errMsg, "use of closed network connection") {
			return true
		}
	}

	// Fallback to SDK's built in retry rules
	return r.DefaultRetryer.ShouldRetry(req)
}
