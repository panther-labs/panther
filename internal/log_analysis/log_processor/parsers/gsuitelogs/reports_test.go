package gsuitelogs

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

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
)

// nolint:lll
func TestParseGSuiteReports(t *testing.T) {
	log := `
{
 "actor": {
   "email": "test@runpanther.io",
   "profileId": "108239653464319429999"
 },
 "etag": "\"JDMC8884sebSczDxOtZ17CIssbQ/THl9MimlCz5ymMYEzJ_WI1bmC50\"",
 "events": [
   {
     "name": "revoke",
     "parameters": [
       {
         "name": "client_id",
         "value": "77185425430.apps.googleusercontent.com"
       },
	{
         "name": "video_send_seconds",
	  "intValue": "1487"
	},
	{
	  "name": "video_send_seconds",
	  "multiIntValue": ["1487","123"]
	},
       {
         "name": "app_name",
         "value": "Google Chrome"
       },
       {
         "name": "client_type",
         "value": "NATIVE_APPLICATION"
       },
       {
         "multiMessageValue": [
           {
             "parameter": [
               {
                 "name": "scope_name",
                 "value": "https://www.google.com/accounts/OAuthLogin"
               },
               {
                 "multiValue": [
                   "IDENTITY"
                 ],
                 "name": "product_bucket"
               }
             ]
           }
         ],
         "name": "scope_data"
       },
       {
         "multiValue": [
           "https://www.google.com/accounts/OAuthLogin"
         ],
         "name": "scope"
       }
     ]
   }
 ],
 "id": {
   "applicationName": "token",
   "customerId": "C045p8dnk",
   "time": "2020-06-10T04:11:42.949Z",
   "uniqueQualifier": "5153173006988512167"
 },
 "kind": "admin#reports#activity"
}
`
	tm := box.Time(time.Date(2020, 6, 10, 4, 11, 42, 949000000, time.UTC))
	event := &Reports{
		Kind: box.String("admin#reports#activity"),
		ID: &ID{
			CustomerID:      box.String("C045p8dnk"),
			ApplicationName: box.String("token"),
			UniqueQualifier: box.String("5153173006988512167"),
			Time:            (*timestamp.RFC3339)(tm),
		},
		Actor: &Actor{
			Email:     box.String("test@runpanther.io"),
			ProfileID: box.String("108239653464319429999"),
		},
		Events: []Event{
			{
				Name: box.String("revoke"),
				Parameters: []Parameter{
					{
						Name:  box.String("client_id"),
						Value: box.String("77185425430.apps.googleusercontent.com"),
					},
					{
						Name:     box.String("video_send_seconds"),
						IntValue: (*numerics.Int64)(box.Int64(1487)),
					},
					{
						Name:          box.String("video_send_seconds"),
						MultiIntValue: []numerics.Int64{numerics.Int64(1487), numerics.Int64((123))},
					},
					{
						Name:  box.String("app_name"),
						Value: box.String("Google Chrome"),
					},
					{
						Name:  box.String("client_type"),
						Value: box.String("NATIVE_APPLICATION"),
					},
					{
						Name:              box.String("scope_data"),
						MultiMessageValue: []jsoniter.RawMessage{(jsoniter.RawMessage)(`{"parameter": [{"name": "scope_name","value": "https://www.google.com/accounts/OAuthLogin"},{"multiValue": ["IDENTITY"],"name": "product_bucket"}]}`)},
					},
					{
						Name:       box.String("scope"),
						MultiValue: []string{"https://www.google.com/accounts/OAuthLogin"},
					},
				},
			},
		},
	}
	event.SetCoreFields("GSuite.Reports", (*timestamp.RFC3339)(tm), &event)
	testutil.CheckPantherParser(t, log, NewReportsParser(), &event.PantherLog)
}

func TestReportsSamples(t *testing.T) {
	samples := testutil.MustReadFileJSONLines("testdata/reportslog_samples.jsonl")
	parser := (&ReportsParser{}).New()
	for i, sample := range samples {
		_, err := parser.Parse(sample)
		assert.NoErrorf(t, err, "failed to parse line %d", i)
	}
}
