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

type metricRuleIDDatum struct {
	Timestamp *time.Time
	Value     *float64
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

	// AnalysisID Metric Events
	numAlertsCreated   = 10.0
	alertsCreatedSmall = metricRuleIDDatum{
		Timestamp: aws.Time(endTime.Add(-15 * time.Minute)),
		Value:     aws.Float64(numAlertsCreated),
	}
	alertsCreatedMedium = metricRuleIDDatum{
		Timestamp: aws.Time(endTime.Add(-15 * time.Minute)),
		Value:     aws.Float64(numAlertsCreated * 10.0),
	}
	alertsCreatedLarge = metricRuleIDDatum{
		Timestamp: aws.Time(endTime.Add(-15 * time.Minute)),
		Value:     aws.Float64(numAlertsCreated * 100.0),
	}
	ruleIDs        = []string{"rule.id.test.small", "rule.id.test.medium", "rule.id.test.large"}
	ruleDimensions = []*cloudwatch.Dimension{
		{
			Name:  aws.String("AnalysisID"),
			Value: aws.String(ruleIDs[0]),
		},
		{
			Name:  aws.String("AnalysisID"),
			Value: aws.String(ruleIDs[1]),
		},
		{
			Name:  aws.String("AnalysisID"),
			Value: aws.String(ruleIDs[2]),
		},
		{
			Name:  aws.String("AnalysisType"),
			Value: aws.String("Rule"),
		},
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

	// Setup a few EventsProcessed test metrics to be retrieved
	err := setupEvents()
	require.NoError(t, err)

	// Setup RuleID test metrics
	err = setupRuleIDEvents()
	require.NoError(t, err)

	// Sleep before querying placed metrics
	time.Sleep(time.Minute)

	t.Run("API", func(t *testing.T) {
		t.Run("GetMetrics", getMetrics)
	})
}

func setupEvents() error {
	_, err := cloudwatchClient.PutMetricData(&cloudwatch.PutMetricDataInput{
		MetricData: []*cloudwatch.MetricDatum{
			// EventsProcessed events
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

	return err
}

func setupRuleIDEvents() error {
	_, err := cloudwatchClient.PutMetricData(&cloudwatch.PutMetricDataInput{
		MetricData: []*cloudwatch.MetricDatum{
			// AlertsCreated Events
			{
				Dimensions: []*cloudwatch.Dimension{
					ruleDimensions[0],
					ruleDimensions[3],
				},
				MetricName: aws.String("AlertsCreated"),
				Timestamp:  alertsCreatedSmall.Timestamp,
				Unit:       aws.String("Count"),
				Value:      alertsCreatedSmall.Value,
			},
			{
				Dimensions: []*cloudwatch.Dimension{
					ruleDimensions[1],
					ruleDimensions[3],
				},
				MetricName: aws.String("AlertsCreated"),
				Timestamp:  alertsCreatedMedium.Timestamp,
				Unit:       aws.String("Count"),
				Value:      alertsCreatedMedium.Value,
			},
			{
				Dimensions: []*cloudwatch.Dimension{
					ruleDimensions[2],
					ruleDimensions[3],
				},
				MetricName: aws.String("AlertsCreated"),
				Timestamp:  alertsCreatedLarge.Timestamp,
				Unit:       aws.String("Count"),
				Value:      alertsCreatedLarge.Value,
			},
		},
		Namespace: aws.String(namespace),
	})

	return err
}

func getMetrics(t *testing.T) {
	// Test EventsProcessed metrics
	getLogTypeMetrics(t)
	// Test AlertsCreated Metrics
	getRuleIDMetrics(t)
}

func getLogTypeMetrics(t *testing.T) {
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

func getRuleIDMetrics(t *testing.T) {
	input := &models.LambdaInput{GetMetrics: &models.GetMetricsInput{
		MetricNames:     []string{"alertsByRuleID"},
		FromDate:        startTime,
		ToDate:          endTime,
		IntervalMinutes: 120,
		Namespace:       namespace,
	}}
	var output models.GetMetricsOutput
	err := genericapi.Invoke(lambdaClient, functionName, input, &output)
	metricResult := output.AlertsByRuleID
	require.NoError(t, err)
	// There should be a single metric per dimension, and three dimensions
	assert.Len(t, metricResult.SingleValue, 3)
	for _, singleValueData := range metricResult.SingleValue {
		// There should be a single series event per dimension (ToDate-FromDate/IntervalMinutes)
		require.NotNil(t, *singleValueData.Label)
		require.Subset(t, ruleIDs, []string{*singleValueData.Label})
		// Verify each dimension got the correct value set
		if *singleValueData.Label == *ruleDimensions[0].Value {
			assert.Equal(t, numAlertsCreated, *singleValueData.Value)
		} else if *singleValueData.Label == *ruleDimensions[1].Value {
			assert.Equal(t, numAlertsCreated*10.0, *singleValueData.Value)
		} else {
			assert.Equal(t, numAlertsCreated*100.0, *singleValueData.Value)
		}
	}
	/** test limit returns only top N events (N=2 in this case)
	input = &models.LambdaInput{GetMetrics: &models.GetMetricsInput{
		MetricNames:     []string{"alertsByRuleID"},
		FromDate:        startTime,
		ToDate:          endTime,
		IntervalMinutes: 120,
		Namespace:       namespace,
		Limit:           2,
	}}
	err = genericapi.Invoke(lambdaClient, functionName, input, &output)
	metricResult = output.AlertsByRuleID
	require.NoError(t, err)
	// There should be a single metric per dimension, and two dimensions
	assert.Len(t, metricResult.SeriesData.Series, 2)
	assert.Len(t, metricResult.SeriesData.Timestamps, 1)
	for _, seriesData := range metricResult.SeriesData.Series {
		// There should be a single metric per dimension (ToDate-FromDate/IntervalMinutes)
		require.Equal(t, len(seriesData.Values), len(metricResult.SeriesData.Timestamps))
		require.NotNil(t, seriesData.Label)
		// This should only have the top two most triggered RuleIDs
		require.Subset(t, ruleIDs, []string{*seriesData.Label})
		require.Greater(t, *seriesData.Values[0], numAlertsCreated)
	}*/
}
