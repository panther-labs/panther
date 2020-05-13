package apachelogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestAccessCombinedParser(t *testing.T) {
	// nolint:lll
	log := `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"`
	tm, err := time.Parse(layoutApacheTimestamp, `[10/Oct/2000:13:55:36 -0700]`)
	require.NoError(t, err)
	event := AccessCombined{
		AccessCommonLog: AccessCommonLog{
			RemoteHostIPAddress: aws.String("127.0.0.1"),
			UserID:              aws.String("frank"),
			RequestTime:         (*timestamp.RFC3339)(&tm),
			RequestMethod:       aws.String("GET"),
			RequestURI:          aws.String("/apache_pb.gif"),
			RequestProtocol:     aws.String("HTTP/1.0"),
			ResponseStatus:      aws.Int16(200),
			ResponseSize:        aws.Int64(2326),
		},
		Referer:   aws.String("http://www.example.com/start.html"),
		UserAgent: aws.String("Mozilla/4.08 [en] (Win98; I ;Nav)"),
	}
	event.PantherEventTime = (*timestamp.RFC3339)(&tm)
	event.PantherLogType = aws.String(TypeAccessCombined)
	event.SetEvent(&event)
	event.AppendAnyIPAddress("127.0.0.1")
	testutil.CheckPantherParser(t, log, NewAccessCombinedParser(), &event.PantherLog)
}
