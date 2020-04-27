package nginxlogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestAccessLog(t *testing.T) {
	//nolint:lll
	log := `180.76.15.143 - - [06/Feb/2019:00:00:38 +0000] "GET / HTTP/1.1" 301 193 "https://domain1.com/?p=1" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.htm$"`

	tm := time.Unix(1549411238, 0).UTC()

	event := &Access{
		RemoteAddress: aws.String("180.76.15.143"),
		Time:          (*timestamp.RFC3339)(&tm),
		Request:       aws.String("GET / HTTP/1.1"),
		Status:        aws.Int16(301),
		BodyBytesSent: aws.Int(193),
		HTTPUserAgent: aws.String(`Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.htm$`),
		HTTPReferer:   aws.String("https://domain1.com/?p=1"),
	}
	testutil.CheckPantherEvent(t, event, TypeAccess, tm,
		parsers.IPAddress("180.76.15.143"),
	)
	testutil.CheckPantherParserJSON(t, log, &AccessParser{}, event)

}

func TestAccessLogWithoutReferer(t *testing.T) {
	//nolint:lll
	log := `180.76.15.143 - - [06/Feb/2019:00:00:38 +0000] "GET / HTTP/1.1" 301 193 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.htm$"`

	tm := time.Unix(1549411238, 0).UTC()

	event := &Access{
		RemoteAddress: aws.String("180.76.15.143"),
		Time:          (*timestamp.RFC3339)(&tm),
		Request:       aws.String("GET / HTTP/1.1"),
		Status:        aws.Int16(301),
		BodyBytesSent: aws.Int(193),
		HTTPUserAgent: aws.String(`Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.htm$`),
	}

	testutil.CheckPantherEvent(t, event, TypeAccess, tm,
		parsers.IPAddress("180.76.15.143"),
	)
	testutil.CheckPantherParserJSON(t, log, &AccessParser{}, event)
}

func TestAccessLogType(t *testing.T) {
	parser := &AccessParser{}
	require.Equal(t, TypeAccess, parser.LogType())
}
