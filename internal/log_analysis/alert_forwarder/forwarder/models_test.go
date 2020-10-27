package forwarder

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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"
)

func TestConvertAttribute(t *testing.T) {
	expectedAlertDedup := &AlertDedupEvent{
		RuleID:              "testRuleId",
		RuleVersion:         "testRuleVersion",
		DeduplicationString: "testDedup",
		AlertCount:          10,
		CreationTime:        time.Unix(1582285279, 0).UTC(),
		UpdateTime:          time.Unix(1582285280, 0).UTC(),
		EventCount:          100,
		LogTypes:            []string{"Log.Type.1", "Log.Type.2"},
		GeneratedTitle:      aws.String("test title"),
		Type:                aws.String("RULE_ERROR"),
		AlertContext:        "{}",
	}

	alertDedupEvent, err := FromDynamodDBAttribute(getNewTestCase())
	require.NoError(t, err)
	require.Equal(t, expectedAlertDedup, alertDedupEvent)
}

func TestConvertNilValue(t *testing.T) {
	alertDedupEvent, err := FromDynamodDBAttribute(nil)
	require.NoError(t, err)
	require.Nil(t, alertDedupEvent)
}

func TestConvertAttributeWithoutOptionalFields(t *testing.T) {
	expectedAlertDedup := &AlertDedupEvent{
		RuleID:              "testRuleId",
		RuleVersion:         "testRuleVersion",
		DeduplicationString: "testDedup",
		AlertCount:          10,
		CreationTime:        time.Unix(1582285279, 0).UTC(),
		UpdateTime:          time.Unix(1582285280, 0).UTC(),
		EventCount:          100,
		AlertContext:        "{}",
		LogTypes:            []string{"Log.Type.1", "Log.Type.2"},
	}

	ddbItem := getNewTestCase()
	delete(ddbItem, "title")
	delete(ddbItem, "alertType")
	alertDedupEvent, err := FromDynamodDBAttribute(ddbItem)
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

func TestMissingRuleVersion(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "ruleVersion")
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

func TestMissingLogTypes(t *testing.T) {
	testInput := getNewTestCase()
	delete(testInput, "logTypes")
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

func TestInvalidTypeShouldntPanic(t *testing.T) {
	testInput := getNewTestCase()
	testInput["alertCreationTime"] = events.NewStringAttribute("string")
	alertDedupEvent, err := FromDynamodDBAttribute(testInput)
	require.Nil(t, alertDedupEvent)
	require.Error(t, err)
}

func getNewTestCase() map[string]events.DynamoDBAttributeValue {
	return map[string]events.DynamoDBAttributeValue{
		"ruleId":            events.NewStringAttribute("testRuleId"),
		"ruleVersion":       events.NewStringAttribute("testRuleVersion"),
		"dedup":             events.NewStringAttribute("testDedup"),
		"alertCount":        events.NewNumberAttribute("10"),
		"alertCreationTime": events.NewNumberAttribute("1582285279"),
		"alertUpdateTime":   events.NewNumberAttribute("1582285280"),
		"eventCount":        events.NewNumberAttribute("100"),
		"logTypes":          events.NewStringSetAttribute([]string{"Log.Type.1", "Log.Type.2"}),
		"title":             events.NewStringAttribute("test title"),
		"status":            events.NewStringAttribute("OPEN"),
		"alertType":         events.NewStringAttribute("RULE_ERROR"),
		"context":           events.NewStringAttribute("{}"),
	}
}
