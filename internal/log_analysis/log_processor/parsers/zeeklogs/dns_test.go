package zeeklogs

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

func TestZeekDNS(t *testing.T) {
	// nolint:lll
	log := `{"ts":1541001600.580233,"uid":"CpR9AY39cUCZ0t5qq6","id.orig_h":"172.16.2.16","id.orig_p":43720,"id.resp_h":"172.16.0.2","id.resp_p":53,"proto":"udp","trans_id":27282,"query":"16.2.16.172.in-addr.arpa", "qtype":1,"rcode":0,"rcode_name":"NOERROR","AA":false,"TC":false,"RD":false,"RA":true,"Z":0,"answers":["ip-172-16-2-16.us-west-2.compute.internal"],"TTLs":[60.0],"rejected":false}`

	expectedTime := time.Date(2018, 10, 31, 16, 0, 0, 580233097, time.UTC)
	expectedEvent := &ZeekDNS{
		TS:        (*timestamp.UnixFloat)(&expectedTime),
		UID:       aws.String("CpR9AY39cUCZ0t5qq6"),
		IDOrigH:   aws.String("172.16.2.16"),
		IDOrigP:   aws.Uint16(43720),
		IDRespH:   aws.String("172.16.0.2"),
		IDRespP:   aws.Uint16(53),
		Proto:     aws.String("udp"),
		TransID:   aws.Uint16(27282),
		Query:     aws.String("16.2.16.172.in-addr.arpa"),
		QType:     aws.Uint64(aQueryType),
		Rcode:     aws.Uint64(0),
		RcodeName: aws.String("NOERROR"),
		AA:        aws.Bool(false),
		TC:        aws.Bool(false),
		RD:        aws.Bool(false),
		RA:        aws.Bool(true),
		Z:         aws.Int(0),
		Answers:   []string{"ip-172-16-2-16.us-west-2.compute.internal"},
		TTLs:      []float64{60.0},
		Rejected:  aws.Bool(false),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Zeek.DNS")
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.IDOrigH)
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.IDRespH)
	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Query)
	expectedEvent.AppendAnyDomainNames(expectedEvent.Answers[0])
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkZeekDNS(t, log, expectedEvent)
}

func TestZeekDNSType(t *testing.T) {
	parser := &ZeekDNSParser{}
	require.Equal(t, "Zeek.DNS", parser.LogType())
}

func checkZeekDNS(t *testing.T, log string, expectedEvent *ZeekDNS) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &ZeekDNSParser{}
	logs, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), logs, err)
}
