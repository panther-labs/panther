package logstream

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
	"strings"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJSONArrayStream(t *testing.T) {
	input := `{ "Records": [` + eventA + "," + eventB + "]}"
	r := strings.NewReader(input)
	s := NewJSONArrayStream(r, 512, "Records")
	assert.Equal(t, eventA, string(s.Next()))
	assert.Equal(t, eventB, string(s.Next()))
	assert.Nil(t, s.Next())
	assert.NoError(t, s.Err())
}

func TestNewJSONArrayStreamEmptyArray(t *testing.T) {
	input := `{ "Records": []}`
	r := strings.NewReader(input)
	s := NewJSONArrayStream(r, 512, "Records")
	assert.Nil(t, s.Next())
	assert.NoError(t, s.Err())
}

func TestNewJSONArrayStreamInvalidPath(t *testing.T) {
	input := `{}`
	r := strings.NewReader(input)
	s := NewJSONArrayStream(r, 512, "Records")
	assert.Nil(t, s.Next())
	assert.Error(t, s.Err())
	assert.Contains(t, s.Err().Error(), `seekJSONPath: key "Records" not found`)
}

func TestNewJSONArrayStreamUnexpectedEOF(t *testing.T) {
	input := `{"Records": `
	r := strings.NewReader(input)
	s := NewJSONArrayStream(r, 512, "Records")
	assert.Nil(t, s.Next())
	assert.Error(t, s.Err())
	assert.Contains(t, s.Err().Error(), `ReadArray: expect [ or , or ] or n, but found`)
}

func TestSeekJSONPath(t *testing.T) {
	type testCase struct {
		Name    string
		Input   string
		Seek    []string
		Expect  string
		WantErr string
	}
	for _, tc := range []testCase{
		{
			"Seek into string",
			`{"Records": "foo"}`,
			[]string{"Records", "1"},
			``,
			`seekJSONPath: cannot seek into a string value`,
		},
		{
			"Seek object key",
			`{"Records": [{"ID":1}]}`,
			[]string{"Records"},
			` [{"ID":1}]`,
			"",
		},
		{
			"Seek array",
			`{"Records": [{"ID":1}]}`,
			[]string{"Records", "0"},
			`{"ID":1}`,
			"",
		},
		{
			"Seek array element",
			`{"Records": [{"ID":1},{"ID":2}]}`,
			[]string{"Records", "1", "ID"},
			`2`,
			"",
		},
		{
			"Seek missing key",
			`{"Records": [{"ID":1},{"ID":2}]}`,
			[]string{"Foo", "1", "ID"},
			``,
			`seekJSONPath: key "Foo" not found`,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			assert := require.New(t)
			r := strings.NewReader(tc.Input)
			iter := jsoniter.Parse(jsoniter.ConfigDefault, r, 512)
			ok := seekJSONPath(iter, tc.Seek)
			if tc.WantErr != "" {
				assert.False(ok)
				// We check error on prefix, the byte # is irrelevant
				assert.Contains(iter.Error.Error(), tc.WantErr)
				return
			}
			assert.NoError(iter.Error)
			assert.True(ok)
			raw := iter.SkipAndAppendBytes(make([]byte, 0, len(tc.Expect)))
			assert.Equal(tc.Expect, string(raw))
		})
	}
}

//nolint:lll
const (
	eventA = `{
        "eventVersion":"1.05",
        "userIdentity":{
          "type":"AWSService",
          "invokedBy":"cloudtrail.amazonaws.com"
        },
        "eventTime":"2018-08-26T14:17:23Z",
        "eventSource":"kms.amazonaws.com",
        "eventName":"GenerateDataKey",
        "awsRegion":"us-west-2",
        "sourceIPAddress":"cloudtrail.amazonaws.com",
        "userAgent":"cloudtrail.amazonaws.com",
        "requestParameters":{
          "keySpec":"AES_256",
          "encryptionContext":{
            "aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail",
            "aws:s3:arn": "arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"
          },
          "keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"
        },
        "responseElements":null,
        "requestID":"3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086",
        "eventID":"7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2",
        "readOnly":true,
        "resources":[
          {"arn":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0","accountId":"888888888888","type":"AWS::KMS::Key"}
        ],
        "eventType":"AwsApiCall",
        "recipientAccountId":"777777777777",
        "sharedEventID":"238c190c-1a30-4756-8e08-19fc36ad1b9f"
      }`
	eventB = `{
        "eventVersion":"1.05",
        "userIdentity":{
          "type":"AssumedRole",
          "principalId":"AROAQXSBWDWTDYDZAXXXX:panther-log-processor",
          "arn":"arn:aws:sts::888888888888:assumed-role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX/panther-log-processor",
          "accountId":"888888888888",
          "accessKeyId":"ASIA123456789EXAMPLE",
          "sessionContext":{
            "sessionIssuer":{
              "type":"Role",
              "principalId":"AROAQXSBWDWTDYDZAXXXX",
              "arn":"arn:aws:iam::888888888888:role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX",
              "accountId":"888888888888",
              "userName":"panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX"
            },
            "attributes":{
              "mfaAuthenticated":"false",
              "creationDate":"2018-02-20T13:13:35Z"
            }
          }
        },
        "eventTime":"2018-08-26T14:17:23Z",
        "eventSource":"kms.amazonaws.com",
        "eventName":"Decrypt",
        "awsRegion":"us-east-1",
        "sourceIPAddress":"1.2.3.4",
        "userAgent":"aws-internal/3 aws-sdk-java/1.11.706 Linux/4.14.77-70.59.amzn1.x86_64 OpenJDK_64-Bit_Server_VM/25.242-b08 java/1.8.0_242 vendor/Oracle_Corporation",
        "requestParameters":{
          "encryptionContext":{
            "aws:lambda:FunctionArn":"arn:aws:lambda:us-east-1:888888888888:function:panther-log-processor"
          },
          "encryptionAlgorithm":"SYMMETRIC_DEFAULT"
        },
        "responseElements":null,
        "requestID": "3c5a008c-80d5-491a-bf76-0cac924f6ebb",
        "eventID":"1852a808-86e8-4b4c-9d4d-01a85b6a39cd",
        "readOnly":true,
        "resources":[
            {"accountId":"888888888888","type":"AWS::KMS::Key","arn":"arn:aws:kms:us-east-1:888888888888:key/90be6df2-db60-4237-ad9b-a49260XXXXX"}
        ],
        "eventType":"AwsApiCall"
      }`
)
