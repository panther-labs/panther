package utils

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import "strings"

type ParsedResourceID struct {
	AccountID string
	Region    string
	Schema    string
}

// GenerateResourceID returns a formatted custom Resource ID.
func GenerateResourceID(awsAccountID string, region string, schema string) string {
	return strings.Join([]string{awsAccountID, region, schema}, ":")
}

func ParseResourceID(resourceID string) *ParsedResourceID {
	parsedResourceID := strings.Split(resourceID, ":")
	if len(parsedResourceID) != 3 {
		return nil
	}
	return &ParsedResourceID{
		AccountID: parsedResourceID[0],
		Region:    parsedResourceID[1],
		Schema:    parsedResourceID[2],
	}
}
