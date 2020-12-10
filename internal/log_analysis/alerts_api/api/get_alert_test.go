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
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

type s3SelectStreamReaderMock struct {
	s3.SelectObjectContentEventStreamReader
	mock.Mock
}

func (m *s3SelectStreamReaderMock) Events() <-chan s3.SelectObjectContentEventStreamEvent {
	args := m.Called()
	return args.Get(0).(<-chan s3.SelectObjectContentEventStreamEvent)
}

func (m *s3SelectStreamReaderMock) Err() error {
	args := m.Called()
	return args.Error(0)
}

type s3Mock struct {
	s3iface.S3API
	mock.Mock
	listObjectsOutput *s3.ListObjectsV2Output
}

func (m *s3Mock) ListObjectsV2Pages(input *s3.ListObjectsV2Input, function func(*s3.ListObjectsV2Output, bool) bool) error {
	args := m.Called(input, function)
	function(m.listObjectsOutput, true)
	return args.Error(0)
}

func (m *s3Mock) SelectObjectContent(input *s3.SelectObjectContentInput) (*s3.SelectObjectContentOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*s3.SelectObjectContentOutput), args.Error(1)
}

func (m *tableMock) ListObjectsV2Pages(input *string) (*table.AlertItem, error) {
	args := m.Called(input)
	return args.Get(0).(*table.AlertItem), args.Error(1)
}

type tableMock struct {
	table.API
	mock.Mock
}

func (m *tableMock) GetAlert(input string) (*table.AlertItem, error) {
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*table.AlertItem), args.Error(1)
}

func (m *tableMock) ListAll(input *models.ListAlertsInput) ([]*table.AlertItem, *string, error) {
	args := m.Called(input)
	return args.Get(0).([]*table.AlertItem), args.Get(1).(*string), args.Error(2)
}

func (m *tableMock) UpdateAlertStatus(input *models.UpdateAlertStatusInput) ([]*table.AlertItem, error) {
	args := m.Called(input)
	return args.Get(0).([]*table.AlertItem), args.Error(1)
}

func (m *tableMock) UpdateAlertDelivery(input *models.UpdateAlertDeliveryInput) (*table.AlertItem, error) {
	args := m.Called(input)
	return args.Get(0).(*table.AlertItem), args.Error(1)
}

func TestGetAlertDoesNotExist(t *testing.T) {
	tableMock := &tableMock{}

	input := &models.GetAlertInput{
		AlertID:        "alertId",
		EventsPageSize: aws.Int(5),
	}

	tableMock.On("GetAlert", "alertId").Return(nil, nil)
	api := API{
		alertsDB: tableMock,
	}
	result, err := api.GetAlert(input)
	require.Nil(t, result)
	require.NoError(t, err)
}

func TestGetPolicyAlert(t *testing.T) {
	api, tableMock, s3Mock := initTest()

	timeNow := time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC)

	input := &models.GetAlertInput{
		AlertID:        "alertId",
		EventsPageSize: aws.Int(1),
	}

	alertItem := &table.AlertItem{
		Type:              "POLICY",
		AlertID:           "alertId",
		RuleID:            "AWS.S3.Bucket.Encryption",
		PolicyID:          "AWS.S3.Bucket.Encryption",
		PolicyVersion:     "L.iGYcpTHTS2sQF5VUBuO9Ompm7bTLwc",
		Status:            "",
		CreationTime:      timeNow,
		UpdateTime:        timeNow,
		Severity:          "INFO",
		ResourceTypes:     []string{"AWS.S3.Bucket"},
		ResourceID:        "arn:aws:s3:::panther-integration-processeddata-test-20201103180759",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
	}

	expectedSummary := &models.AlertSummary{
		AlertID:           "alertId",
		RuleID:            aws.String("AWS.S3.Bucket.Encryption"),
		PolicyID:          "AWS.S3.Bucket.Encryption",
		Status:            "OPEN",
		Type:              "POLICY",
		PolicyVersion:     "L.iGYcpTHTS2sQF5VUBuO9Ompm7bTLwc",
		RuleVersion:       aws.String(""),
		DedupString:       aws.String(""),
		Severity:          aws.String("INFO"),
		Title:             aws.String("arn:aws:s3:::panther-integration-processeddata-test-20201103180759"),
		CreationTime:      aws.Time(timeNow),
		UpdateTime:        aws.Time(timeNow),
		EventsMatched:     aws.Int(0),
		LogTypes:          []string{},
		ResourceTypes:     []string{"AWS.S3.Bucket"},
		ResourceID:        "arn:aws:s3:::panther-integration-processeddata-test-20201103180759",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
		DeliveryResponses: []*models.DeliveryResponse{},
	}

	tableMock.On("GetAlert", "alertId").Return(alertItem, nil).Once()

	result, err := api.GetAlert(input)
	require.NoError(t, err)
	require.Equal(t, &models.GetAlertOutput{
		AlertSummary:           *expectedSummary,
		Events:                 []*string{},
		EventsLastEvaluatedKey: aws.String("eyJsb2dUeXBlVG9Ub2tlbiI6e319"),
	}, result)
	s3Mock.AssertExpectations(t)
	tableMock.AssertExpectations(t)
}

func TestGetRuleAlert(t *testing.T) {
	api, tableMock, s3Mock := initTest()

	// The S3 object keys returned by S3 List objects command
	s3Mock.listObjectsOutput = &s3.ListObjectsV2Output{
		Contents: []*s3.Object{{Key: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010100Z-uuid4.json.gz")}}, // nolint:lll
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
		ResourceTypes:     []string{},
		ResourceID:        "",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
		DeliveryResponses: []*models.DeliveryResponse{},
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
		Expression:     aws.String("SELECT * FROM S3Object o WHERE o.p_alert_id='alertId'"),
	}

	eventChannel := getChannel("testEvent")
	mockS3EventReader := &s3SelectStreamReaderMock{}
	selectObjectOutput := &s3.SelectObjectContentOutput{
		EventStream: &s3.SelectObjectContentEventStream{
			Reader: mockS3EventReader,
		},
	}

	tableMock.On("GetAlert", "alertId").Return(alertItem, nil).Once()
	s3Mock.On("ListObjectsV2Pages", expectedListObjectsRequest, mock.Anything).Return(nil).Once()
	s3Mock.On("SelectObjectContent", expectedSelectObjectInput).Return(selectObjectOutput, nil).Once()
	mockS3EventReader.On("Events").Return(eventChannel)
	mockS3EventReader.On("Err").Return(nil)

	result, err := api.GetAlert(input)
	require.NoError(t, err)
	require.Equal(t, &models.GetAlertOutput{
		AlertSummary: *expectedSummary,
		Events:       aws.StringSlice([]string{"testEvent"}),
		EventsLastEvaluatedKey:
		// nolint
		aws.String("eyJsb2dUeXBlVG9Ub2tlbiI6eyJsb2d0eXBlIjp7InMzT2JqZWN0S2V5IjoicnVsZXMvbG9ndHlwZS95ZWFyPTIwMjAvbW9udGg9MDEvZGF5PTAxL2hvdXI9MDEvcnVsZV9pZD1ydWxlSWQvMjAyMDAxMDFUMDEwMTAwWi11dWlkNC5qc29uLmd6IiwiZXZlbnRJbmRleCI6MX19fQ=="),
	}, result)
	s3Mock.AssertExpectations(t)
	tableMock.AssertExpectations(t)

	// now test paging...

	api, tableMock, s3Mock = initTest() // reset mocks

	input.EventsExclusiveStartKey = result.EventsLastEvaluatedKey // set paginator

	expectedPagedListObjectsRequest := &s3.ListObjectsV2Input{
		Bucket:     aws.String(api.env.ProcessedDataBucket),
		Prefix:     aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/"),
		StartAfter: aws.String("rules/logtype/year=2020/month=01/day=01/hour=01/rule_id=ruleId/20200101T010100Z-uuid4.json.gz"),
	}

	// returns nothing
	noopMockS3EventReader := &s3SelectStreamReaderMock{}
	noopSelectObjectOutput := &s3.SelectObjectContentOutput{
		EventStream: &s3.SelectObjectContentEventStream{
			Reader: noopMockS3EventReader,
		},
	}
	noopMockS3EventReader.On("Events").Return(getChannel())
	noopMockS3EventReader.On("Err").Return(nil)

	// nothing comes back from the listing
	s3Mock.listObjectsOutput = &s3.ListObjectsV2Output{}

	tableMock.On("GetAlert", "alertId").Return(alertItem, nil).Once()
	s3Mock.On("SelectObjectContent", expectedSelectObjectInput).Return(noopSelectObjectOutput, nil).Once()
	s3Mock.On("ListObjectsV2Pages", expectedPagedListObjectsRequest, mock.Anything).Return(nil).Once()
	result, err = api.GetAlert(input)
	require.NoError(t, err)
	require.Equal(t, &models.GetAlertOutput{
		AlertSummary: *expectedSummary,
		Events:       aws.StringSlice([]string{}),
		EventsLastEvaluatedKey:
		// nolint
		aws.String("eyJsb2dUeXBlVG9Ub2tlbiI6eyJsb2d0eXBlIjp7InMzT2JqZWN0S2V5IjoicnVsZXMvbG9ndHlwZS95ZWFyPTIwMjAvbW9udGg9MDEvZGF5PTAxL2hvdXI9MDEvcnVsZV9pZD1ydWxlSWQvMjAyMDAxMDFUMDEwMTAwWi11dWlkNC5qc29uLmd6IiwiZXZlbnRJbmRleCI6MH19fQ=="),
	}, result)

	s3Mock.AssertExpectations(t)
	tableMock.AssertExpectations(t)
}

func TestGetAlertFilterOutS3KeysOutsideTheTimePeriod(t *testing.T) {
	api, tableMock, s3Mock := initTest()

	// The S3 object keys returned by S3 List objects command
	s3Mock.listObjectsOutput = &s3.ListObjectsV2Output{
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
		ResourceTypes:     []string{},
		ResourceID:        "",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: time.Date(2020, 1, 1, 1, 59, 0, 0, time.UTC),
		DeliveryResponses: []*models.DeliveryResponse{},
	}

	eventChannel := getChannel("testEvent")
	mockS3EventReader := &s3SelectStreamReaderMock{}
	selectObjectOutput := &s3.SelectObjectContentOutput{
		EventStream: &s3.SelectObjectContentEventStream{
			Reader: mockS3EventReader,
		},
	}

	tableMock.On("GetAlert", "alertId").Return(alertItem, nil).Once()
	s3Mock.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(nil).Once()
	s3Mock.On("SelectObjectContent", mock.Anything).Return(selectObjectOutput, nil).Once()
	mockS3EventReader.On("Events").Return(eventChannel)
	mockS3EventReader.On("Err").Return(nil)

	result, err := api.GetAlert(input)
	require.NoError(t, err)
	require.Equal(t, &models.GetAlertOutput{
		AlertSummary: *expectedSummary,
		Events:       aws.StringSlice([]string{"testEvent"}),
		EventsLastEvaluatedKey:
		// nolint
		aws.String("eyJsb2dUeXBlVG9Ub2tlbiI6eyJsb2d0eXBlIjp7InMzT2JqZWN0S2V5IjoicnVsZXMvbG9ndHlwZS95ZWFyPTIwMjAvbW9udGg9MDEvZGF5PTAxL2hvdXI9MDEvcnVsZV9pZD1ydWxlSWQvMjAyMDAxMDFUMDEwNTAwWi11dWlkNC5qc29uLmd6IiwiZXZlbnRJbmRleCI6MX19fQ=="),
	}, result)
	s3Mock.AssertExpectations(t)
	tableMock.AssertExpectations(t)
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

func initTest() (*API, *tableMock, *s3Mock) {
	tableMock := &tableMock{}
	s3Mock := &s3Mock{}

	api := &API{
		alertsDB: tableMock,
		s3Client: s3Mock,
		env: envConfig{
			ProcessedDataBucket: "bucket",
		},
	}

	return api, tableMock, s3Mock
}
