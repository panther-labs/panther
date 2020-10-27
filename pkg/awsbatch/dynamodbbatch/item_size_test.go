package dynamodbbatch

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDynamoItemSize(t *testing.T) {
	justStrings := map[string]*dynamodb.AttributeValue{
		"first":  {S: aws.String("firstValue")},
		"second": {S: aws.String("now with spaces")},
		"bytes":  {S: aws.String("ooh unicode ⌘")},
		"group":  {SS: []*string{aws.String("an element"), aws.String("an other element"), aws.String("福")}},
	}
	size := GetDynamoItemSize(justStrings)
	assert.Equal(t, 90, size)

	stringsAndBytes := map[string]*dynamodb.AttributeValue{
		"string":   {S: aws.String("ooh unicode ⌘")},
		"bytes":    {B: []byte("lots of of cool bytes")},
		"byte set": {BS: [][]byte{[]byte("an element"), []byte("an other element"), []byte("福")}},
	}
	size = GetDynamoItemSize(stringsAndBytes)
	assert.Equal(t, 84, size)

	stringsAndBytesAndNums := map[string]*dynamodb.AttributeValue{
		"bytes":      {B: []byte("lots of of cool bytes")},
		"string":     {S: aws.String("ooh unicode ⌘")},
		"number set": {NS: []*string{aws.String("110"), aws.String("33")}},
		"numbers":    {N: aws.String("1603137254")},
	}
	size = GetDynamoItemSize(stringsAndBytesAndNums)
	assert.Equal(t, 75, size)

	// Mix & match, contains maps, lists, nested maps in lists, nulls, bools, numbers, strings,
	// and string sets
	smallResource := `{"attributes":{"M":{"AccountId":{"S":"123456789012"},"GlobalEventSelectors":{"L":[{"M":{"DataResources":{"NULL":true},"ExcludeManagementEventSources":{"NULL":true},"IncludeManagementEvents":{"BOOL":true},"ReadWriteType":{"S":"All"}}}]},"Name":{"S":"AWS.CloudTrail.Meta"},"Region":{"S":"global"},"ResourceId":{"S":"123456789012::AWS.CloudTrail.Meta"},"ResourceType":{"S":"AWS.CloudTrail.Meta"},"Tags":{"NULL":true},"TimeCreated":{"NULL":true},"Trails":{"L":[{"S":"arn:aws:cloudtrail:us-west-1:123456789012:trail/us-west-1-test-trail"},{"S":"arn:aws:cloudtrail:us-west-2:123456789012:trail/event-processor-testing"},{"S":"arn:aws:cloudtrail:us-west-2:123456789012:trail/ABCDEFGHJIKLMNOPQRSTUVWTrail"},{"S":"arn:aws:cloudtrail:us-west-2:123456789012:trail/Another"}]}}},"deleted":{"BOOL":false},"expiresAt":{"N":"1603137254"},"id":{"S":"123456789012::AWS.CloudTrail.Meta"},"integrationId":{"S":"1111aa1a-6428-4cdc-b9b3-222"},"integrationType":{"S":"aws"},"lastModified":{"S":"2020-01-01T00:00:00.803361683Z"},"lowerId":{"S":"123456789012::aws.cloudtrail.meta"},"type":{"S":"AWS.CloudTrail.Meta"}}` // nolint: lll

	var testThing map[string]*dynamodb.AttributeValue
	err := jsoniter.Unmarshal([]byte(smallResource), &testThing)
	require.NoError(t, err)
	assert.Equal(t, 788, GetDynamoItemSize(testThing))
}
