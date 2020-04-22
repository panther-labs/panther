package osseclogs

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

func TestEventInfo(t *testing.T) {
	//nolint:lll
	log := `{"rule":{"level":5,"comment":"Syslogd restarted.","sidid":1005,"group":"syslog,errors,"},"id":"1510376401.0","TimeStamp":1510376401000,"location":"/var/log/messages","full_log":"Nov 11 00:00:01 ix syslogd[72090]: restart","hostname":"ix","program_name":"syslogd"}`

	expectedTime := time.Unix(1510376401, 0).UTC()

	expectedEvent := &EventInfo{
		Rule: &Rule{
			Level:   aws.Int(5),
			Comment: aws.String("Syslogd restarted."),
			SIDID:   aws.Int(1005),
			Group:   aws.String("syslog,errors,"),
		},
		ID:          aws.String("1510376401.0"),
		Timestamp:   (*timestamp.UnixMillisecond)(&expectedTime),
		Location:    aws.String("/var/log/messages"),
		FullLog:     aws.String("Nov 11 00:00:01 ix syslogd[72090]: restart"),
		Hostname:    aws.String("ix"),
		ProgramName: aws.String("syslogd"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("OSSEC.EventInfo")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkEventInfo(t, log, expectedEvent)
}

func TestEventInfoWithSyscheckFile(t *testing.T) {
	//nolint:lll
	log := `{"rule":{"level":7,"comment":"Integrity checksum changed.","sidid":550,"group":"ossec,syscheck,"},"id":"1540845340.16991","TimeStamp":1540845340000,"decoder":"syscheck_integrity_changed","location":"syscheck","full_log":"Integrity checksum changed for:'/usr/bin/ssm-cli'\nOld md5sum was:'22271cce0732d887e3980e5a6868e459'\nNew md5sum is :'220a8f105af5e711f99e52583209a871'\nOld sha1sum was:'4df65340f366c18f85be228c26817e20391f32c4'\nNew sha1sum is :'c7414fd048c81361720e2d9c8d2f82faf33748b6'\n","SyscheckFile":{"path":"/usr/bin/ssm-cli","md5_before":"22271cce0732d887e3980e5a6868e459","md5_after":"220a8f105af5e711f99e52583209a871","sha1_before":"4df65340f366c18f85be228c26817e20391f32c4","sha1_after":"c7414fd048c81361720e2d9c8d2f82faf33748b6"},"hostname":"ip-172-16-2-16"}`

	expectedTime := time.Unix(1540845340, 0).UTC()

	//nolint:lll
	expectedEvent := &EventInfo{
		Rule: &Rule{
			Level:   aws.Int(7),
			Comment: aws.String("Integrity checksum changed."),
			SIDID:   aws.Int(550),
			Group:   aws.String("ossec,syscheck,"),
		},
		ID:        aws.String("1540845340.16991"),
		Timestamp: (*timestamp.UnixMillisecond)(&expectedTime),
		Decoder:   aws.String("syscheck_integrity_changed"),
		Location:  aws.String("syscheck"),
		FullLog:   aws.String("Integrity checksum changed for:'/usr/bin/ssm-cli'\nOld md5sum was:'22271cce0732d887e3980e5a6868e459'\nNew md5sum is :'220a8f105af5e711f99e52583209a871'\nOld sha1sum was:'4df65340f366c18f85be228c26817e20391f32c4'\nNew sha1sum is :'c7414fd048c81361720e2d9c8d2f82faf33748b6'\n"),
		SyscheckFile: &FileDiff{
			MD5After:   aws.String("220a8f105af5e711f99e52583209a871"),
			MD5Before:  aws.String("22271cce0732d887e3980e5a6868e459"),
			SHA1After:  aws.String("c7414fd048c81361720e2d9c8d2f82faf33748b6"),
			SHA1Before: aws.String("4df65340f366c18f85be228c26817e20391f32c4"),
			Path:       aws.String("/usr/bin/ssm-cli"),
		},
		Hostname: aws.String("ip-172-16-2-16"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("OSSEC.EventInfo")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyMD5Hashes("220a8f105af5e711f99e52583209a871", "22271cce0732d887e3980e5a6868e459")
	expectedEvent.AppendAnySHA1Hashes("c7414fd048c81361720e2d9c8d2f82faf33748b6", "4df65340f366c18f85be228c26817e20391f32c4")

	checkEventInfo(t, log, expectedEvent)
}

func TestEventInfoType(t *testing.T) {
	parser := &EventInfoParser{}
	require.Equal(t, "OSSEC.EventInfo", parser.LogType())
}

func checkEventInfo(t *testing.T, log string, expectedEvent *EventInfo) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &EventInfoParser{}
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
