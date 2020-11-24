package oktalogs

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
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestSystemLogParser(t *testing.T) {
	log := `{
		"version": "0",
		"severity": "INFO",
		"client": {
			"zone": "OFF_NETWORK",
			"device": "Unknown",
			"userAgent": {
			"os": "Unknown",
			"browser": "UNKNOWN",
			"rawUserAgent": "UNKNOWN-DOWNLOAD"
			},
			"ipAddress": "12.97.85.90"
		},
		"actor": {
			"id": "00u1qw1mqitPHM8AJ0g7",
			"type": "User",
			"alternateId": "admin@tc1-trexcloud.com",
			"displayName": "John Fung"
		},
		"outcome": {
			"result": "SUCCESS"
		},
		"uuid": "f790999f-fe87-467a-9880-6982a583986c",
		"published": "2017-09-30T22:23:07.777Z",
		"eventType": "user.session.start",
		"displayMessage": "User login to Okta",
		"transaction": {
			"type": "WEB",
			"id": "V04Oy4ubUOc5UuG6s9DyNQAABtc"
		},
		"debugContext": {
			"debugData": {
			"requestUri": "/login/do-login"
			}
		},
		"legacyEventType": "core.user_auth.login_success",
		"authenticationContext": {
			"authenticationStep": 0,
			"externalSessionId": "1013FfF-DKQSvCI4RVXChzX-w"
		}
	}`
	tm, err := time.Parse(time.RFC3339Nano, "2017-09-30T22:23:07.777Z")
	require.NoError(t, err)
	event := LogEvent{
		Version:  aws.String("0"),
		Severity: aws.String("INFO"),
		Client: &Client{
			Zone:   aws.String("OFF_NETWORK"),
			Device: aws.String("Unknown"),
			UserAgent: &UserAgent{
				Browser:      aws.String("UNKNOWN"),
				OS:           aws.String("Unknown"),
				RawUserAgent: aws.String("UNKNOWN-DOWNLOAD"),
			},
			IPAddress: aws.String("12.97.85.90"),
		},
		Actor: &Actor{
			ID:          aws.String("00u1qw1mqitPHM8AJ0g7"),
			Type:        aws.String("User"),
			AlternateID: aws.String("admin@tc1-trexcloud.com"),
			DisplayName: aws.String("John Fung"),
		},
		Outcome: &Outcome{
			Result: aws.String("SUCCESS"),
		},
		UUID:           aws.String("f790999f-fe87-467a-9880-6982a583986c"),
		Published:      (*timestamp.RFC3339)(&tm),
		EventType:      aws.String("user.session.start"),
		DisplayMessage: aws.String("User login to Okta"),
		Transaction: &Transaction{
			Type: aws.String("WEB"),
			ID:   aws.String("V04Oy4ubUOc5UuG6s9DyNQAABtc"),
		},
		DebugContext: &DebugContext{
			DebugData: jsoniter.RawMessage(`{"requestUri": "/login/do-login"}`),
		},
		LegacyEventType: aws.String("core.user_auth.login_success"),
		AuthenticationContext: &AuthenticationContext{
			AuthenticationStep: aws.Int32(0),
			ExternalSessionID:  aws.String("1013FfF-DKQSvCI4RVXChzX-w"),
		},
	}
	event.SetCoreFields(TypeSystemLog, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyIPAddress("12.97.85.90")
	testutil.CheckPantherParser(t, log, NewSystemLogParser(), &event.PantherLog)
}

func TestSystemLogJSONSamples(t *testing.T) {
	samples := testutil.MustReadFileJSONLines("testdata/oktalogs_systemlog_samples.jsonl")
	parser := NewSystemLogParser()
	valid := validator.New()
	for _, sample := range samples {
		results, err := parser.Parse(sample)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		for _, result := range results {
			event := result.Event()
			require.NoError(t, valid.Struct(event))
		}
	}
}
