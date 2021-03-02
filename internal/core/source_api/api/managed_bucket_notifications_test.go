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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/require"
)

var (
	topic  = aws.String("arn:aws:sns:us-east-1:123456789:test-topic")
	events = aws.StringSlice([]string{"s3:ObjectCreated:*"})
)

type sortableTopicConfigs []*s3.TopicConfiguration

func (c sortableTopicConfigs) Len() int            { return len(c) }
func (c sortableTopicConfigs) Less(i, j int) bool  { return prefixFilter(c[i]) < prefixFilter(c[j]) }
func (c sortableTopicConfigs) Swap(i, j int)       { c[i], c[j] = c[j], c[i] }
func prefixFilter(c *s3.TopicConfiguration) string { return *c.Filter.Key.FilterRules[0].Value }

func Test_updateTopicConfigs(t *testing.T) {
	t.Parallel()

	requireEqualSorted := func(t *testing.T, expected, actual []*s3.TopicConfiguration, msgAndArgs ...interface{}) {
		for _, configs := range [][]*s3.TopicConfiguration{expected, actual} {
			for _, c := range configs {
				if strings.HasPrefix(*c.Id, namePrefix) {
					// Remove the UUID suffix to facilitate equality testing. We only care it's Panther-managed.
					*c.Id = namePrefix
				}
			}
		}
		sort.Sort(sortableTopicConfigs(expected))
		sort.Sort(sortableTopicConfigs(actual))
		require.Equal(t, expected, actual, msgAndArgs)
	}

	t.Run("add to empty configs", func(t *testing.T) {
		t.Parallel()
		var bucketTopicConfigs []*s3.TopicConfiguration // bucket hasn't any SNS notifications set up
		prefixes := []string{"prefixa/", "prefixb/"}    // create bucket configs for these prefixes

		topicConfigs, newManagedConfigIDs := updateTopicConfigs(bucketTopicConfigs, prefixes, topic)

		expected := []*s3.TopicConfiguration{
			topicConfig(newManagedConfigIDs[0], "prefix", "prefixa/", events, topic),
			topicConfig(newManagedConfigIDs[1], "prefix", "prefixb/", events, topic),
		}

		requireEqualSorted(t, expected, topicConfigs)
		require.Len(t, newManagedConfigIDs, 2)
	})

	t.Run("existing Panther and user configs ", func(t *testing.T) {
		t.Parallel()
		bucketTopicConfigs := []*s3.TopicConfiguration{
			topicConfig("id1", "prefix", "userPrefixA/", events, topic),
			topicConfig("panther-managed-123", "prefix", "pantherPrefix/", events, topic),
			topicConfig("id2", "prefix", "userPrefixB/", events, topic),
		}
		// Note pantherPrefix from above is missing. These should be the only Panther-managed configs.
		prefixes := []string{"pantherPrefix1/", "pantherPrefix2/"}

		topicConfigs, newManagedConfigIDs := updateTopicConfigs(bucketTopicConfigs, prefixes, topic)

		expected := []*s3.TopicConfiguration{
			topicConfig("id1", "prefix", "userPrefixA/", events, topic),
			topicConfig("id2", "prefix", "userPrefixB/", events, topic),
			topicConfig(newManagedConfigIDs[0], "prefix", "pantherPrefix1/", events, topic),
			topicConfig(newManagedConfigIDs[1], "prefix", "pantherPrefix2/", events, topic),
		}
		requireEqualSorted(t, expected, topicConfigs)
		require.Len(t, newManagedConfigIDs, 2)
	})

	t.Run("remove all Panther-managed configs", func(t *testing.T) {
		t.Parallel()
		bucketTopicConfigs := []*s3.TopicConfiguration{
			topicConfig("id1", "prefix", "userPrefixA/", events, topic),
			topicConfig("panther-managed-1", "prefix", "pantherPrefix1/", events, topic),
			topicConfig("id2", "prefix", "userPrefixB/", events, topic),
			topicConfig("panther-managed-2", "prefix", "pantherPrefix2/", events, topic),
		}
		var prefixes []string // No Panther-managed configs should be kept after the operation

		topicConfigs, newManagedConfigIDs := updateTopicConfigs(bucketTopicConfigs, prefixes, topic)

		expected := []*s3.TopicConfiguration{
			topicConfig("id1", "prefix", "userPrefixA/", events, topic),
			topicConfig("id2", "prefix", "userPrefixB/", events, topic),
		}
		requireEqualSorted(t, expected, topicConfigs)
		require.Len(t, newManagedConfigIDs, 0)
	})

	t.Run("override Panther-managed configs", func(t *testing.T) {
		t.Parallel()
		bucketTopicConfigs := []*s3.TopicConfiguration{
			topicConfig("panther-managed-1", "prefix", "aaa", events, topic),
			topicConfig("panther-managed-2", "prefix", "bbb", events, topic),
		}
		// We want to set an empty prefix to the bucket notification. This may happen if a source is updated
		// or created and has a blank prefix filter.
		prefixes := []string{""}

		topicConfigs, newManagedConfigIDs := updateTopicConfigs(bucketTopicConfigs, prefixes, topic)

		expected := []*s3.TopicConfiguration{
			topicConfig(newManagedConfigIDs[0], "prefix", "", events, topic),
		}
		require.Equal(t, expected, topicConfigs)
		require.Len(t, newManagedConfigIDs, 1)
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

func topicConfig(id, filterType, filterValue string, events []*string, topicARN *string) *s3.TopicConfiguration {
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
