package laceworklogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestLaceworkAws(t *testing.T) {
	//nolint:lll
	log := `{
		"EVENT_CATEGORY": "App",
		"EVENT_DETAILS": {
			"data": [
				{
					"START_TIME": "2020-07-08T09:00:00Z",
					"END_TIME": "2020-07-08T09:00:00Z",
					"EVENT_MODEL": "PtypeConn",
					"EVENT_TYPE": "NewInternalConnection",
					"ENTITY_MAP": {
						"Container": [
							{
								"HAS_EXTERNAL_CONNS": 0,
								"IMAGE_TAG": "xxx",
								"IS_SERVER": 1,
								"FIRST_SEEN_TIME": "2020-07-08T09:00:00Z",
								"IMAGE_REPO": "xxx",
								"IS_CLIENT": 0
							}
						],
						"User": [
							{
								"MACHINE_HOSTNAME": "ip-10-0-64-135",
								"USERNAME": "root"
							}
						],
						"Process": [
							{
								"HOSTNAME": "ip-10-0-64-135",
								"CMDLINE": "xxx",
								"PROCESS_START_TIME": "2020-07-08T09:00:00Z",
								"CPU_PERCENTAGE": 0.02,
								"PROCESS_ID": 25325
							}
						],
						"Machine": [
							{
								"EXTERNAL_IP": "",
								"CPU_PERCENTAGE": 10.61
							}
						],
						"SourceIpAddress": [
							{
								"IP_ADDRESS": "169.254.169.254"
							}
						],
						"IpAddress": [
							{
								"IP_ADDRESS": "0.0.0.0"
							}
						]
					},
					"EVENT_ACTOR": "App",
					"EVENT_ID": "16206"
				}
			]
		},
		"SEVERITY": 5,
		"START_TIME": "08 Jul 2020 09:00 GMT",
		"SUMMARY": "xxx",
		"EVENT_TYPE": "NewInternalConnection",
		"EVENT_NAME": "New Internal Connection",
		"LINK": "www.example.com",
		"EVENT_ID": 16206,
		"ACCOUNT": "HCP",
		"SOURCE": "Lacework Agent"
	}`

	expectedDate := time.Date(2020, 7, 8, 9, 0, 0, 0, time.UTC)
	expectedEvent := &Lacework{
		EventCategory: aws.String("App"),
		Severity:      (*numerics.Integer)(aws.Int(5)),
		StartTime:     (*timestamp.LaceworkTimestamp)(&expectedDate),
		Summary:       aws.String("xxx"),
		EventType:     aws.String("NewInternalConnection"),
		EventName:     aws.String("New Internal Connection"),
		Link:          aws.String("www.example.com"),
		EventID:       (*numerics.Integer)(aws.Int(16206)),
		Account:       aws.String("HCP"),
		Source:        aws.String("Lacework Agent"),

		EventDetails: &LaceworkDataArray{
			Data: []LaceworkData{{
				StartTime:  (*timestamp.RFC3339)(&expectedDate),
				EndTime:    (*timestamp.RFC3339)(&expectedDate),
				EventModel: aws.String("PtypeConn"),
				EventType:  aws.String("NewInternalConnection"),
				EventActor: aws.String("App"),
				EventID:    aws.String("16206"),
				EntityMap: &LaceworkEntityMap{
					Container: []LaceworkContainer{
						{
							HasExternalConns: (*numerics.Integer)(aws.Int(0)),
							ImageTag:         aws.String("xxx"),
							IsServer:         (*numerics.Integer)(aws.Int(1)),
							FirstSeenTime:    (*timestamp.RFC3339)(&expectedDate),
							ImageRepo:        aws.String("xxx"),
							IsClient:         (*numerics.Integer)(aws.Int(0)),
						},
					},
					User: []LaceworkUser{
						{
							Hostname: aws.String("ip-10-0-64-135"),
							Username: aws.String("root"),
						},
					},
					Process: []LaceworkProcess{
						{
							Hostname:         aws.String("ip-10-0-64-135"),
							CommandLine:      aws.String("xxx"),
							ProcessStartTime: (*timestamp.RFC3339)(&expectedDate),
							CPUPercentage:    aws.Float32(0.02),
							ProcessID:        (*numerics.Integer)(aws.Int(25325)),
						},
					},
					Machine: []LaceworkMachine{
						{
							ExternalIP:    aws.String(""),
							CPUPercentage: aws.Float32(10.61),
						},
					},
					SourceIPAddress: []LaceworkSourceIPAddress{
						{
							SourceIPAddress: aws.String("169.254.169.254"),
						},
					},
					IPAddress: []LaceworkIPAddress{
						{
							SourceIPAddress: aws.String("0.0.0.0"),
						},
					},
				},
			}},
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Lacework.Events")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDate)
	expectedEvent.AppendAnyIPAddress("169.254.169.254")
	expectedEvent.AppendAnyIPAddress("0.0.0.0")

	checkLaceworkLog(t, log, expectedEvent)
}

func TestLaceworkLogType(t *testing.T) {
	parser := &LaceworkParser{}
	require.Equal(t, "Lacework.Events", parser.LogType())
}

func checkLaceworkLog(t *testing.T, log string, expectedEvent *Lacework) {
	parser := (&LaceworkParser{}).New()
	expectedEvent.SetEvent(expectedEvent)
	result, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), result, err)
}
