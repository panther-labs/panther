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
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type sourceCache struct {
	// last time the cache was updated
	cacheUpdateTime time.Time
	// sources by id
	index map[string]*models.SourceIntegration
	// sources by s3 bucket sorted by longest prefix first
	byBucket map[string][]prefixSource
}

type prefixSource struct {
	prefix string
	source *models.SourceIntegration
}

// LoadS3 loads the source configuration for an S3 object.
// This will update the cache if needed.
// It will return error if it encountered an issue retrieving the source information
func (c *sourceCache) LoadS3(bucketName, objectKey string) (*models.SourceIntegration, error) {
	if err := c.Sync(time.Now()); err != nil {
		return nil, err
	}
	return c.FindS3(bucketName, objectKey), nil
}

// Loads the source configuration for an source id.
// This will update the cache if needed.
// It will return error if it encountered an issue retrieving the source information or if the source is not found.
func (c *sourceCache) Load(id string) (*models.SourceIntegration, error) {
	if err := c.Sync(time.Now()); err != nil {
		return nil, err
	}
	src := c.Find(id)
	if src != nil {
		return src, nil
	}
	return nil, errors.Errorf("source %q not found", id)
}

// Sync will update the cache if too much time has passed
func (c *sourceCache) Sync(now time.Time) error {
	if c.cacheUpdateTime.Add(sourceCacheDuration).Before(now) {
		// we need to update the cache
		input := &models.LambdaInput{
			ListIntegrations: &models.ListIntegrationsInput{},
		}
		var output []*models.SourceIntegration
		if err := genericapi.Invoke(common.LambdaClient, sourceAPIFunctionName, input, &output); err != nil {
			return err
		}
		c.Update(now, output)
	}
	return nil
}

// Update updates the cache
func (c *sourceCache) Update(now time.Time, sources []*models.SourceIntegration) {
	byBucket := make(map[string][]prefixSource)
	index := make(map[string]*models.SourceIntegration)
	for _, source := range sources {
		bucket, prefixes := source.S3Info()
		for _, prefix := range prefixes {
			byBucket[bucket] = append(byBucket[bucket], prefixSource{prefix: prefix, source: source})
		}
		index[source.IntegrationID] = source
	}
	// Sort sources for each bucket.
	// It is important to have the sources sorted by longest prefix first.
	// This ensures that longer prefixes (ie `/foo/bar`) have precedence over shorter ones (ie `/foo`).
	// This is especially important for the empty prefix as it would match all objects in a bucket making
	// other sources invalid.
	for _, sources := range byBucket {
		sources := sources
		sort.Slice(sources, func(i, j int) bool {
			// Sort by prefix length descending
			return len(sources[i].prefix) > len(sources[j].prefix)
		})
	}
	*c = sourceCache{
		byBucket:        byBucket,
		index:           index,
		cacheUpdateTime: now,
	}
}

// Find looks up a source by id without updating the cache
func (c *sourceCache) Find(id string) *models.SourceIntegration {
	return c.index[id]
}

// FindS3 looks up a source by bucket name and prefix without updating the cache
func (c *sourceCache) FindS3(bucketName, objectKey string) *models.SourceIntegration {
	prefixSourcesOrdered := c.byBucket[bucketName]
	for _, s := range prefixSourcesOrdered {
		if strings.HasPrefix(objectKey, s.prefix) {
			return s.source
		}
	}
	return nil
}
