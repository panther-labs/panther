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
	"net/http"

	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type RuleCache interface {
	Get(id, version string) (*models.Rule, error)
}

// s3ClientCacheKey -> S3 client
type LRUCache struct {
	cache      *lru.ARCCache
	ruleClient gatewayapi.API
}

func NewCache(ruleClient gatewayapi.API) *LRUCache {
	cache, err := lru.NewARC(1000)
	if err != nil {
		panic("failed to create cache")
	}
	return &LRUCache{
		cache:      cache,
		ruleClient: ruleClient,
	}
}

func (c *LRUCache) Get(id, version string) (*models.Rule, error) {
	value, ok := c.cache.Get(cacheKey(id, version))
	if !ok {
		rule, err := c.getRule(id, version)
		if err != nil {
			return nil, err
		}
		value = rule
		c.cache.Add(cacheKey(id, version), value)
	}
	return value.(*models.Rule), nil
}

func cacheKey(id, version string) string {
	return id + ":" + version
}

func (c *LRUCache) getRule(id, version string) (*models.Rule, error) {
	zap.L().Debug("calling analysis API to retrieve information for rule", zap.String("ruleId", id), zap.String("ruleVersion", version))
	input := models.LambdaInput{
		GetRule: &models.GetRuleInput{ID: id, VersionID: version},
	}
	var rule models.Rule

	httpStatus, err := c.ruleClient.Invoke(&input, &rule)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch information for ruleID [%s], version [%s]", id, version)
	}
	if httpStatus != http.StatusOK {
		return nil, errors.Errorf("failed to fetch information for ruleID [%s], version [%s], got HTTP response [%d]", id, version, httpStatus)
	}
	return &rule, nil
}
