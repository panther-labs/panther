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
	"strings"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/forwarder"
)

type SQSClassifier struct {
	Resolver    pantherlog.ParserResolver
	LoadSource  func(id string) (*models.SourceIntegration, error)
	stats       classification.ClassifierStats
	classifiers map[string]classification.ClassifierAPI
}

var _ classification.ClassifierAPI = (*SQSClassifier)(nil)

func (c *SQSClassifier) Classify(log string) (*classification.ClassifierResult, error) {
	log = strings.TrimSpace(log)
	if len(log) == 0 {
		c.stats.LogLineCount++
		return &classification.ClassifierResult{}, nil
	}
	msg := forwarder.Message{}
	err := pantherlog.ConfigJSON().UnmarshalFromString(log, &msg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse JSON message")
	}
	cls, ok := c.classifiers[msg.SourceIntegrationID]
	if !ok {
		cls, err = c.buildSourceClassifier(msg.SourceIntegrationID)

		if err != nil {
			// Just update the stats
			return nil, err
		}
		if c.classifiers == nil {
			c.classifiers = map[string]classification.ClassifierAPI{}
		}
		c.classifiers[msg.SourceIntegrationID] = cls
	}
	return cls.Classify(msg.Payload)
}

func (c *SQSClassifier) buildSourceClassifier(id string) (classification.ClassifierAPI, error) {
	src, err := c.LoadSource(id)
	if err != nil {
		return nil, err
	}
	return BuildClassifier(src.SqsConfig.LogTypes, src, c.Resolver)
}

func (c *SQSClassifier) Stats() *classification.ClassifierStats {
	stats := &classification.ClassifierStats{}
	stats.Add(&c.stats)
	for _, child := range c.classifiers {
		stats.Add(child.Stats())
	}
	return stats
}

func (c *SQSClassifier) ParserStats() map[string]*classification.ParserStats {
	stats := map[string]*classification.ParserStats{}
	for _, child := range c.classifiers {
		childStats := child.ParserStats()
		if childStats == nil {
			continue
		}
		classification.MergeParserStats(stats, childStats)
	}
	return stats
}
