package forwarder

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/require"
)

func TestConvertAttribute(t *testing.T) {
	expectedAlertDedup := &AlertDedupEvent{
		RuleID:              "testRuleId",
		DeduplicationString: "testDedup",
		AlertCount:          10,
		CreationTime:        time.Unix(1582285279, 0).UTC(),
		UpdateTime:          time.Unix(1582285280, 0).UTC(),
		Severity:            "INFO",
		EventPerLogType: map[string]int64{
			"LogType1": 5,
			"LogType2": 10,
		},
	}

	alertDedupEvent, err := FromDynamodDBAttribute(getNewTestCase())
	require.NoError(t, err)
	require.Equal(t, expectedAlertDedup, alertDedupEvent)
}

func TestMissingRuleId(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "ruleId")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func TestMissingDedup(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "dedup")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func TestMissingAlertCount(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "alertCount")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func TestMissingAlertCreationTime(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "alertCreationTime")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func TestMissingAlertUpdateTime(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "alertUpdateTime")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func TestMissingEventsPerLogTypeLogType(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "eventsPerLogType")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func TestMissingSeverity(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "severity")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func TestInvalidInteger(t *testing.T) {
	testInput := getNewTestCase()
	testInput["alertCreationTime"] = events.NewNumberAttribute("notaninteger")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func getNewTestCase() map[string]events.DynamoDBAttributeValue {
	return map[string]events.DynamoDBAttributeValue{
		"ruleId":            events.NewStringAttribute("testRuleId"),
		"dedup":             events.NewStringAttribute("testDedup"),
		"alertCount":        events.NewNumberAttribute("10"),
		"alertCreationTime": events.NewNumberAttribute("1582285279"),
		"alertUpdateTime":   events.NewNumberAttribute("1582285280"),
		"eventCount":        events.NewNumberAttribute("100"),
		"severity":          events.NewStringAttribute("INFO"),
		"eventsPerLogType": events.NewMapAttribute(
			map[string]events.DynamoDBAttributeValue{
				"LogType1": events.NewNumberAttribute("5"),
				"LogType2": events.NewNumberAttribute("10"),
			}),
	}
}
