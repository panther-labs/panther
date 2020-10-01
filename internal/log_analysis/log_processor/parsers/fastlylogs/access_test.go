package fastlylogs

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/apachelogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const clfTimestampFormat = `[02/Jan/2006:15:04:05 -0700]`

func TestCLFParser(t *testing.T) {
	log := `127.0.0.1 "-" "-" [11/Sep/2020:13:20:27 +0000] "GET / HTTP/1.1" 404 345`
	tm, err := time.Parse(clfTimestampFormat, `[11/Sep/2020:13:20:27 +0000]`)
	require.NoError(t, err)
	event := Access{
		AccessCommonLog: apachelogs.AccessCommonLog{
			RemoteHostIPAddress:   aws.String("127.0.0.1"),
			ClientIdentityRFC1413: nil,
			UserID:                nil,
			RequestTime:           (*timestamp.RFC3339)(&tm),
			RequestMethod:         aws.String("GET"),
			RequestURI:            aws.String("/"),
			RequestProtocol:       aws.String("HTTP/1.1"),
			ResponseStatus:        aws.Int16(404),
			ResponseSize:          aws.Int64(345),
		},
	}
	event.PantherEventTime = (*timestamp.RFC3339)(&tm)
	event.PantherLogType = aws.String(TypeAccess)
	event.SetEvent(&event)
	event.AppendAnyIPAddress("127.0.0.1")
	testutil.CheckPantherParser(t, log, &AccessParser{}, &event.PantherLog)
}

func TestCLFParserEmptyResponseSize(t *testing.T) {
	log := `127.0.0.1 "-" "-" [11/Sep/2020:13:20:27 +0000] "GET / HTTP/1.1" 404 -`
	tm, err := time.Parse(clfTimestampFormat, `[11/Sep/2020:13:20:27 +0000]`)
	require.NoError(t, err)
	event := Access{
		AccessCommonLog: apachelogs.AccessCommonLog{
			RemoteHostIPAddress:   aws.String("127.0.0.1"),
			ClientIdentityRFC1413: nil,
			UserID:                nil,
			RequestTime:           (*timestamp.RFC3339)(&tm),
			RequestMethod:         aws.String("GET"),
			RequestURI:            aws.String("/"),
			RequestProtocol:       aws.String("HTTP/1.1"),
			ResponseStatus:        aws.Int16(404),
			ResponseSize:          aws.Int64(0),
		},
	}
	event.PantherEventTime = (*timestamp.RFC3339)(&tm)
	event.PantherLogType = aws.String(TypeAccess)
	event.SetEvent(&event)
	event.AppendAnyIPAddress("127.0.0.1")
	testutil.CheckPantherParser(t, log, &AccessParser{}, &event.PantherLog)
}
