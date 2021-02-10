package sources

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

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

func TestSourceCacheStructFind(t *testing.T) {
	cache := sourceCache{}
	now := time.Now()
	sources := []*models.SourceIntegration{
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "1",
				IntegrationType:  models.IntegrationTypeAWS3,
				S3Bucket:         "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "", LogTypes: []string{"Foo.Bar"}}},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "2",
				IntegrationType:  models.IntegrationTypeAWS3,
				S3Bucket:         "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "foo", LogTypes: []string{"Foo.Baz"}}},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "3",
				IntegrationType:  models.IntegrationTypeAWS3,
				S3Bucket:         "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "foo/bar/sqs", LogTypes: []string{"Foo.Sqs"}}},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "4",
				IntegrationType:  models.IntegrationTypeAWS3,
				S3Bucket:         "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "foo/bar/baz", LogTypes: []string{"Foo.Qux"}}},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:   "5",
				IntegrationType: models.IntegrationTypeAWS3,
				S3Bucket:        "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{
					{S3Prefix: "bar/bar/bar/bar", LogTypes: []string{"Foo.Qux"}},
					{S3Prefix: "foo/foo/foo", LogTypes: []string{"Foo.Qux"}},
					{S3Prefix: "foo/bar/baz/prefix", LogTypes: []string{"Foo.Qux"}},
				},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:   "6",
				IntegrationType: models.IntegrationTypeAWS3,
				// Different bucket with similar prefixes as some other source.
				S3Bucket: "bar",
				S3PrefixLogTypes: models.S3PrefixLogtypes{
					{S3Prefix: "bar/bar/bar/bar", LogTypes: []string{"Foo.Qux"}},
					{S3Prefix: "foo/foo/foo", LogTypes: []string{"Foo.Qux"}},
					{S3Prefix: "foo/bar/baz/prefix", LogTypes: []string{"Foo.Qux"}},
				},
			},
		},
	}
	assert := require.New(t)
	cache.Update(now, sources)
	{
		src := cache.FindS3("foo", "bar")
		assert.NotNil(src)
		assert.Equal("1", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar.json")
		assert.NotNil(src)
		assert.Equal("2", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar/baz.json")
		assert.NotNil(src)
		assert.Equal("4", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar/sqs/test.json")
		assert.NotNil(src)
		assert.Equal("3", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar/baz/qux.json")
		assert.NotNil(src)
		assert.Equal("4", src.IntegrationID)
	}
	{
		src := cache.FindS3("goo", "foo/bar/baz/qux.json")
		assert.Nil(src)
	}
	{
		src := cache.FindS3("foo", "foo/bar/baz/prefix/qux.json")
		assert.NotNil(src)
		assert.Equal("5", src.IntegrationID)
	}
	{
		src := cache.FindS3("bar", "foo/bar/baz/prefix/qux.json")
		assert.Equal("6", src.IntegrationID)
	}
	{
		src := cache.FindS3("bar", "foo/foo/foo/prefix/qux.json")
		assert.Equal("6", src.IntegrationID)
	}
}
