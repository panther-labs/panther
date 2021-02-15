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
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/require"
)

var (
	topic  = aws.String("arn:aws:sns:us-east-1:123456789:test-topic")
	events = aws.StringSlice([]string{"s3:ObjectCreated:*"})
)

func Test_updateTopicConfigs(t *testing.T) {
	t.Run("add to empty configs", func(t *testing.T) {
		var bucketTopicConfigs []*s3.TopicConfiguration // bucket hasn't any SNS notifications set up
		var managedConfigIDs []string                   // Panther hasn't created anything yet
		prefixes := []string{"prefixa/", "prefixb/"}    // create bucket configs for these prefixes

		topicConfigs, newManagedConfigIDs := updateTopicConfigs(bucketTopicConfigs, managedConfigIDs, prefixes, topic)

		expected := []*s3.TopicConfiguration{
			topicConfig(events, "prefix", "prefixa/", newManagedConfigIDs[0], topic),
			topicConfig(events, "prefix", "prefixb/", newManagedConfigIDs[1], topic),
		}

		require.Equal(t, expected, topicConfigs)
		require.Len(t, newManagedConfigIDs, 2)
	})

	t.Run("existing Panther and user configs ", func(t *testing.T) {
		bucketTopicConfigs := []*s3.TopicConfiguration{
			topicConfig(events, "prefix", "userPrefixA/", "id1", topic),
			topicConfig(events, "prefix", "pantherPrefix/", "id3", topic),
			topicConfig(events, "prefix", "userPrefixB/", "id2", topic),
		}
		managedConfigIDs := []string{"id3"}
		// Note pantherPrefix from above is missing. These should be the only Panther-managed configs.
		prefixes := []string{"pantherPrefix1/", "pantherPrefix2/"}

		topicConfigs, newManagedConfigIDs := updateTopicConfigs(bucketTopicConfigs, managedConfigIDs, prefixes, topic)

		expected := []*s3.TopicConfiguration{
			topicConfig(events, "prefix", "userPrefixA/", "id1", topic),
			topicConfig(events, "prefix", "userPrefixB/", "id2", topic),
			topicConfig(events, "prefix", "pantherPrefix1/", newManagedConfigIDs[0], topic),
			topicConfig(events, "prefix", "pantherPrefix2/", newManagedConfigIDs[1], topic),
		}
		require.Equal(t, expected, topicConfigs)
		require.Len(t, newManagedConfigIDs, 2)
	})

	t.Run("remove all Panther-managed configs", func(t *testing.T) {
		bucketTopicConfigs := []*s3.TopicConfiguration{
			topicConfig(events, "prefix", "userPrefixA/", "id1", topic),
			topicConfig(events, "prefix", "pantherPrefix1/", "panther-managed-1", topic),
			topicConfig(events, "prefix", "userPrefixB/", "id2", topic),
			topicConfig(events, "prefix", "pantherPrefix2/", "panther-managed-2", topic),
		}
		managedConfigIDs := []string{"panther-managed-1", "panther-managed-2"}
		prefixes := []string{} // No Panther-managed configs should be kept after the operation

		topicConfigs, newManagedConfigIDs := updateTopicConfigs(bucketTopicConfigs, managedConfigIDs, prefixes, topic)

		expected := []*s3.TopicConfiguration{
			topicConfig(events, "prefix", "userPrefixA/", "id1", topic),
			topicConfig(events, "prefix", "userPrefixB/", "id2", topic),
		}
		require.Equal(t, expected, topicConfigs)
		require.Len(t, newManagedConfigIDs, 0)
	})
}

func Test_reduceNoPrefixes(t *testing.T) {
	test := func(input, expected []string) {
		actual := reduceNoPrefixStrings(input)
		sort.Strings(actual)
		sort.Strings(expected)
		require.Equal(t, expected, actual)
	}
	{
		input := []string{"abc", "", "prefix"}
		expected := []string{""}
		test(input, expected)
	}
	{
		input := []string{"abc", "abcd"}
		expected := []string{"abc"}
		test(input, expected)
	}
	{
		input := []string{
			"prefix", "abcc", "abc", "abc", "abcd", "b", "xy", "xyz", "abc123", "xyz123", "pref", "prefi",
		}
		expected := []string{"pref", "xy", "abc", "b"}
		test(input, expected)
	}
	{
		input := []string{"a", "a", "aaa", "ab", "ba", "aaaaa", "aa"}
		expected := []string{"a", "ba"}
		test(input, expected)
	}
}

func topicConfig(events []*string, filterType, filterValue, id string, topicARN *string) *s3.TopicConfiguration {
	return &s3.TopicConfiguration{
		Events: events,
		Filter: &s3.NotificationConfigurationFilter{
			Key: &s3.KeyFilter{
				FilterRules: []*s3.FilterRule{
					{
						Name:  &filterType,
						Value: &filterValue,
					},
				},
			},
		},
		Id:       &id,
		TopicArn: topicARN,
	}
}
