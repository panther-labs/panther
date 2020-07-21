package main

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
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/metrics/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	functionName = "panther-metrics-api"
)

type metricDatum struct {
	Timestamp *time.Time
	Value     *float64
	LogType   *string
}

var (
	integrationTest  bool
	sess             *session.Session
	lambdaClient     *lambda.Lambda
	cloudwatchClient *cloudwatch.CloudWatch
	endTime          = time.Now()
	roundedEndTime   = endTime.Truncate(1 * time.Minute)
	startTime        = endTime.Add(-2*time.Hour + 5*time.Minute)
	roundedStartTime = startTime.Truncate(1 * time.Minute)

	// Append a timestamp to the namespace so that we can pick out just the metrics we care about
	namespace  = "ZZZPantherIntegrationTest" + strconv.Itoa(int(endTime.Unix()))
	dimensions = []*cloudwatch.Dimension{
		{
			Name:  aws.String("LogType"),
			Value: aws.String("IntegrationTest1"),
		},
		{
			Name:  aws.String("LogType"),
			Value: aws.String("IntegrationTest2"),
		},
	}

	firstEvent = metricDatum{
		Timestamp: aws.Time(endTime.Add(-90 * time.Minute)),
		Value:     aws.Float64(100),
		LogType:   nil,
	}
	secondEvent = metricDatum{
		Timestamp: aws.Time(endTime.Add(-30 * time.Minute)),
		Value:     aws.Float64(250),
		LogType:   nil,
	}
	thirdEvent = metricDatum{
		Timestamp: aws.Time(endTime.Add(-15 * time.Minute)),
		Value:     aws.Float64(125),
		LogType:   nil,
	}
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	os.Exit(m.Run())
}

func TestIntegration(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	sess = session.Must(session.NewSession())
	lambdaClient = lambda.New(sess)
	cloudwatchClient = cloudwatch.New(sess)

	// Setup a few test metrics to be retrieved
	err := setupEvents()
	require.NoError(t, err)

	t.Run("API", func(t *testing.T) {
		t.Run("GetMetrics", getMetrics)
	})
}

func setupEvents() error {
	_, err := cloudwatchClient.PutMetricData(&cloudwatch.PutMetricDataInput{
		MetricData: []*cloudwatch.MetricDatum{
			{
				Dimensions: []*cloudwatch.Dimension{
					dimensions[0], // Type 1
				},
				MetricName: aws.String("EventsProcessed"),
				Timestamp:  firstEvent.Timestamp,
				Unit:       aws.String("Count"),
				Value:      firstEvent.Value,
			},
			{
				Dimensions: []*cloudwatch.Dimension{
					dimensions[0], // Type 1
				},
				MetricName: aws.String("EventsProcessed"),
				Timestamp:  secondEvent.Timestamp,
				Unit:       aws.String("Count"),
				Value:      secondEvent.Value,
			},
			{
				Dimensions: []*cloudwatch.Dimension{
					dimensions[1], // Type 2
				},
				MetricName: aws.String("EventsProcessed"),
				Timestamp:  thirdEvent.Timestamp,
				Unit:       aws.String("Count"),
				Value:      thirdEvent.Value,
			},
		},
		Namespace: aws.String(namespace),
	})

	time.Sleep(time.Minute)
	return err
}

func getMetrics(t *testing.T) {
	input := &models.LambdaInput{GetMetrics: &models.GetMetricsInput{
		MetricNames:     []string{"eventsProcessed"},
		FromDate:        startTime,
		ToDate:          endTime,
		IntervalMinutes: 60,
		Namespace:       namespace,
	}}
	var output models.GetMetricsOutput
	err := genericapi.Invoke(lambdaClient, functionName, input, &output)
	require.NoError(t, err)

	assert.Equal(t, roundedStartTime.UTC(), output.FromDate.UTC())
	assert.Equal(t, roundedEndTime.UTC(), output.ToDate.UTC())
	assert.Equal(t, input.GetMetrics.IntervalMinutes, output.IntervalMinutes)

	metricResult := output.EventsProcessed
	assert.Empty(t, metricResult.SingleValue)

	// There should be two entries in series data, one for each unique combination of dimensions
	assert.Len(t, metricResult.SeriesData.Series, 2)
	assert.Len(t, metricResult.SeriesData.Timestamps, 2)
	for _, seriesData := range metricResult.SeriesData.Series {
		require.Equal(t, len(seriesData.Values), len(metricResult.SeriesData.Timestamps))
		require.NotNil(t, seriesData.Label)
		require.Subset(t, []string{"IntegrationTest1", "IntegrationTest2"}, []string{*seriesData.Label})
		if *seriesData.Label == "IntegrationTest1" {
			require.Len(t, seriesData.Values, 2)
			assert.Equal(t, seriesData.Values[1], firstEvent.Value)
			assert.Equal(t, seriesData.Values[0], secondEvent.Value)
		} else {
			require.Len(t, seriesData.Values, 2)
			assert.Equal(t, seriesData.Values[0], thirdEvent.Value)
			assert.Equal(t, *seriesData.Values[1], float64(0))
		}
	}
}
