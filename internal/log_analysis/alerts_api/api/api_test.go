package api

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

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	token = &EventPaginationToken{LogTypeToToken: map[string]*LogTypeToken{
		"logtype": {
			EventIndex:  1,
			S3ObjectKey: "s3Key",
		},
	},
	}
	// nolint:gosec
	tokenEncoded = "eyJsb2dUeXBlVG9Ub2tlbiI6eyJsb2d0eXBlIjp7InMzT2JqZWN0S2V5IjoiczNLZXkiLCJldmVudEluZGV4IjoxfX19"
)

func TestPaginationTokenEncode(t *testing.T) {
	result, err := token.encode()
	require.NoError(t, err)
	require.Equal(t, tokenEncoded, result)
}

func TestPaginationTokenDecode(t *testing.T) {
	result, err := decodePaginationToken(tokenEncoded)
	require.NoError(t, err)
	require.Equal(t, token, result)
}

func TestInvalidTokenDecode(t *testing.T) {
	_, err := decodePaginationToken("notatoken")
	require.Error(t, err)
}
