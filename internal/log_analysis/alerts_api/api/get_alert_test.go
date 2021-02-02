package api

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
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	rulemodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestGetAlertDoesNotExist(t *testing.T) {
	tableMock := &tableMock{}

	input := &models.GetAlertInput{
		AlertID:        "alertId",
		EventsPageSize: aws.Int(5),
	}

	tableMock.On("GetAlert", "alertId").Return((*table.AlertItem)(nil), nil)
	api := API{
		alertsDB: tableMock,
	}
	result, err := api.GetAlert(input)
	require.Nil(t, result)
	require.NoError(t, err)
	tableMock.AssertExpectations(t)
}

func TestGetRuleAlert(t *testing.T) {
	api := initTestAPI()

	// The S3 object keys returned by S3 List objects command
	page := &s3.ListObjectsV2Output{
		Contents: []*s3.Object{
			{Key: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010100Z-uuid4.json.gz")},
			{Key: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010101Z-uuid4.json.gz")},
		}, // nolint:lll
	}

	input := &models.GetAlertInput{
		AlertID:        "alertId",
		EventsPageSize: aws.Int(1),
	}

	alertItem := &table.AlertItem{
		AlertID:           "alertId",
		RuleID:            "ruleId",
		Status:            "",
		RuleVersion:       "ruleVersion",
		DedupString:       "dedupString",
		CreationTime:      time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC),
		UpdateTime:        time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
		Severity:          "INFO",
		EventCount:        5,
		LogTypes:          []string{"logtype"},
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
	}

	expectedSummary := &models.AlertSummary{
		AlertID:           "alertId",
		RuleID:            aws.String("ruleId"),
		Status:            "OPEN",
		Type:              "RULE",
		RuleVersion:       aws.String("ruleVersion"),
		Severity:          aws.String("INFO"),
		Title:             aws.String("ruleId"),
		DedupString:       aws.String("dedupString"),
		CreationTime:      aws.Time(time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC)),
		UpdateTime:        aws.Time(time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC)),
		EventsMatched:     aws.Int(5),
		LogTypes:          []string{"logtype"},
		ResourceID:        "",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
	}

	expectedListObjectsRequest := &s3.ListObjectsV2Input{
		Bucket:     aws.String(api.env.ProcessedDataBucket),
		Prefix:     aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/"),
		StartAfter: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010000Z"),
	}

	expectedSelectObjectInput := &s3.SelectObjectContentInput{
		Bucket: aws.String(api.env.ProcessedDataBucket),
		Key:    aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010100Z-uuid4.json.gz"),
		InputSerialization: &s3.InputSerialization{
			CompressionType: aws.String(s3.CompressionTypeGzip),
			JSON:            &s3.JSONInput{Type: aws.String(s3.JSONTypeLines)},
		},
		OutputSerialization: &s3.OutputSerialization{
			JSON: &s3.JSONOutput{RecordDelimiter: aws.String("\n")},
		},
		ExpressionType: aws.String(s3.ExpressionTypeSql),
		Expression:     aws.String("SELECT * FROM S3Object o WHERE o.p_alert_id='alertId' LIMIT 1"),
	}

	api.mockTable.On("GetAlert", "alertId").Return(alertItem, nil).Once()
	api.mockS3.On("ListObjectsV2PagesWithContext", mock.Anything, expectedListObjectsRequest, mock.Anything, mock.Anything).
		Return(page, nil).Once()

	eventChannel1 := getChannel("testEvent1")
	mockS3EventReader1 := &testutils.S3SelectStreamReaderMock{}
	selectObjectOutput1 := &s3.SelectObjectContentOutput{
		EventStream: &s3.SelectObjectContentEventStream{
			Reader: mockS3EventReader1,
		},
	}
	api.mockS3.On("SelectObjectContentWithContext", mock.Anything, expectedSelectObjectInput, mock.Anything).
		Return(selectObjectOutput1, nil).Once()
	mockS3EventReader1.On("Events").Return(eventChannel1)
	mockS3EventReader1.On("Err").Return(nil)

	eventChannel2 := getChannel("testEvent2")
	mockS3EventReader2 := &testutils.S3SelectStreamReaderMock{}
	selectObjectOutput2 := &s3.SelectObjectContentOutput{
		EventStream: &s3.SelectObjectContentEventStream{
			Reader: mockS3EventReader2,
		},
	}
	api.mockS3.On("SelectObjectContentWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(selectObjectOutput2, nil).Once()
	mockS3EventReader2.On("Events").Return(eventChannel2)
	mockS3EventReader2.On("Err").Return(nil)

	api.mockRuleCache.On("Get", "ruleId", "ruleVersion").Return(&rulemodels.Rule{}, nil).Once()
	result, err := api.GetAlert(input)
	require.NoError(t, err)
	expectedOutput := &models.GetAlertOutput{
		AlertSummary: *expectedSummary,
		Events:       []string{"testEvent1"},
		EventsLastEvaluatedKey:
		// nolint
		aws.String("eyJsb2dUeXBlVG9Ub2tlbiI6eyJsb2d0eXBlIjp7InMzT2JqZWN0S2V5IjoicnVsZXMvbG9ndHlwZS95ZWFyPTIwMjAvbW9udGg9MDEvZGF5PTAxL2hvdXI9MDEvcnVsZV9pZD1ydWxlSWQvMjAyMDAxMDFUMDEwMTAwWi11dWlkNC5qc29uLmd6IiwiZXZlbnRJbmRleCI6MX19fQ=="),
	}
	assert.Equal(t, expectedOutput, result)
	api.AssertExpectations(t)

	// now test paging...

	api = initTestAPI()                                           // reset mocks
	input.EventsExclusiveStartKey = result.EventsLastEvaluatedKey // set paginator

	// extend LIMIT since we are paging and S3 select has no OFFSET support
	expectedSelectObjectInput.Expression = aws.String("SELECT * FROM S3Object o WHERE o.p_alert_id='alertId' LIMIT 2")

	expectedPagedListObjectsRequest := &s3.ListObjectsV2Input{
		Bucket:     aws.String(api.env.ProcessedDataBucket),
		Prefix:     aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/"),
		StartAfter: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010100Z-uuid4.json.gz"),
	}

	// returns nothing
	noopMockS3EventReader := &testutils.S3SelectStreamReaderMock{}
	noopSelectObjectOutput := &s3.SelectObjectContentOutput{
		EventStream: &s3.SelectObjectContentEventStream{
			Reader: noopMockS3EventReader,
		},
	}
	noopMockS3EventReader.On("Events").Return(getChannel())
	noopMockS3EventReader.On("Err").Return(nil)

	// nothing comes back from the listing
	page = &s3.ListObjectsV2Output{}

	api.mockTable.On("GetAlert", "alertId").Return(alertItem, nil).Once()
	api.mockS3.On("SelectObjectContentWithContext", mock.Anything, expectedSelectObjectInput, mock.Anything).
		Return(noopSelectObjectOutput, nil).Once()
	api.mockS3.On("ListObjectsV2PagesWithContext", mock.Anything, expectedPagedListObjectsRequest, mock.Anything, mock.Anything).
		Return(page, nil).Once()
	api.mockRuleCache.On("Get", "ruleId", "ruleVersion").Return(&rulemodels.Rule{}, nil).Once()
	result, err = api.GetAlert(input)
	require.NoError(t, err)
	require.Equal(t, &models.GetAlertOutput{
		AlertSummary: *expectedSummary,
		Events:       nil,
		EventsLastEvaluatedKey:
		// nolint
		aws.String("eyJsb2dUeXBlVG9Ub2tlbiI6eyJsb2d0eXBlIjp7InMzT2JqZWN0S2V5IjoicnVsZXMvbG9ndHlwZS95ZWFyPTIwMjAvbW9udGg9MDEvZGF5PTAxL2hvdXI9MDEvcnVsZV9pZD1ydWxlSWQvMjAyMDAxMDFUMDEwMTAwWi11dWlkNC5qc29uLmd6IiwiZXZlbnRJbmRleCI6MH19fQ=="),
	}, result)

	api.AssertExpectations(t)
}

func TestGetAlertFilterOutS3KeysOutsideTheTimePeriod(t *testing.T) {
	api := initTestAPI()

	// The S3 object keys returned by S3 List objects command
	page := &s3.ListObjectsV2Output{
		Contents: []*s3.Object{
			// The object was created at year=2020, month=01, day=01, hour=01, minute=02, second=00, which is before the alert was created
			// We should skip this object
			{Key: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010200Z-uuid4.json.gz")},
			// The object was created at year=2020, month=01, day=01, hour=01, minute=05, second=00
			{Key: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010500Z-uuid4.json.gz")},
			// The object was created at year=2020, month=01, day=01, hour=01, minute=10, second=00, which is after the alert was update
			// We should skip this object
			{Key: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010200Z-uuid4.json.gz")},
		},
	}

	input := &models.GetAlertInput{
		AlertID:        "alertId",
		EventsPageSize: aws.Int(5),
	}

	alertItem := &table.AlertItem{
		AlertID:           "alertId",
		RuleID:            "ruleId",
		Status:            "",
		RuleVersion:       "ruleVersion",
		CreationTime:      time.Date(2020, 1, 1, 1, 5, 0, 0, time.UTC),
		UpdateTime:        time.Date(2020, 1, 1, 1, 6, 0, 0, time.UTC),
		Severity:          "INFO",
		EventCount:        5,
		DedupString:       "dedupString",
		LogTypes:          []string{"logtype"},
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
	}
	expectedSummary := &models.AlertSummary{
		AlertID:           "alertId",
		RuleID:            aws.String("ruleId"),
		Status:            "OPEN",
		Type:              "RULE",
		RuleVersion:       aws.String("ruleVersion"),
		Title:             aws.String("ruleId"),
		CreationTime:      aws.Time(time.Date(2020, 1, 1, 1, 5, 0, 0, time.UTC)),
		UpdateTime:        aws.Time(time.Date(2020, 1, 1, 1, 6, 0, 0, time.UTC)),
		EventsMatched:     aws.Int(5),
		Severity:          aws.String("INFO"),
		DedupString:       aws.String("dedupString"),
		LogTypes:          []string{"logtype"},
		ResourceID:        "",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
	}

	eventChannel := getChannel("testEvent")
	mockS3EventReader := &testutils.S3SelectStreamReaderMock{}
	selectObjectOutput := &s3.SelectObjectContentOutput{
		EventStream: &s3.SelectObjectContentEventStream{
			Reader: mockS3EventReader,
		},
	}

	api.mockTable.On("GetAlert", "alertId").Return(alertItem, nil).Once()
	api.mockS3.On("ListObjectsV2PagesWithContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(page, nil).Once()
	api.mockS3.On("SelectObjectContentWithContext", mock.Anything, mock.Anything, mock.Anything).Return(selectObjectOutput, nil).Once()
	mockS3EventReader.On("Events").Return(eventChannel)
	mockS3EventReader.On("Err").Return(nil)
	api.mockRuleCache.On("Get", "ruleId", "ruleVersion").Return(&rulemodels.Rule{}, nil).Once()
	result, err := api.GetAlert(input)
	require.NoError(t, err)
	require.Equal(t, &models.GetAlertOutput{
		AlertSummary: *expectedSummary,
		Events:       []string{"testEvent"},
		EventsLastEvaluatedKey:
		// nolint
		aws.String("eyJsb2dUeXBlVG9Ub2tlbiI6eyJsb2d0eXBlIjp7InMzT2JqZWN0S2V5IjoicnVsZXMvbG9ndHlwZS95ZWFyPTIwMjAvbW9udGg9MDEvZGF5PTAxL2hvdXI9MDEvcnVsZV9pZD1ydWxlSWQvMjAyMDAxMDFUMDEwNTAwWi11dWlkNC5qc29uLmd6IiwiZXZlbnRJbmRleCI6MX19fQ=="),
	}, result)
	api.AssertExpectations(t)
}

// Returns an channel that emulated S3 Select channel
func getChannel(events ...string) <-chan s3.SelectObjectContentEventStreamEvent {
	channel := make(chan s3.SelectObjectContentEventStreamEvent, len(events))
	for _, event := range events {
		channel <- &s3.RecordsEvent{
			Payload: []byte(event),
		}
	}
	close(channel)
	return channel
}
