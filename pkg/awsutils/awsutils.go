package awsutils

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
)

// Method returns true if the provided error is an AWS error with any
// of the given codes.
func IsAnyError(err error, codes ...string) bool {
	if err == nil {
		return false
	}
	var awserror awserr.Error
	if !errors.As(err, &awserror) {
		return false
	}
	for _, code := range codes {
		if awserror.Code() == code {
			return true
		}
	}
	return false
}

// Helper struct for creating AWS policy documents and marshalling them into json.
type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}
type StatementEntry struct {
	Sid       string
	Effect    string
	Action    string
	Resource  string    `json:",omitempty"`
	Principal Principal `json:",omitempty"`
}
type Principal struct {
	Service string `json:",omitempty"`
	AWS     string `json:",omitempty"`
}
