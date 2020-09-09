package sources

import (
	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/forwarder"
	"github.com/pkg/errors"
	"strings"
)

var jsonAPI = common.BuildJSON()

type SQSClassifier struct {
	Registry    *logtypes.Registry
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
	err := jsonAPI.UnmarshalFromString(log, &msg)
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
	return BuildClassifier(src, c.Registry)
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
