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
	"context"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// LoadSource loads the source configuration for an source id.
// This will update the global cache if needed.
// It will return error if it encountered an issue retrieving the source information or if the source is not found.
func LoadSource(id string) (*models.SourceIntegration, error) {
	return globalSourceCache.Load(id)
}

// LoadSourceS3 loads the source configuration for an S3 object.
// It will update the global cache if needed
// It will return error if it encountered an issue retrieving the source information or if the source is not found.
func LoadSourceS3(bucketName, objectKey string) (*models.SourceIntegration, error) {
	result, err := globalSourceCache.LoadS3(bucketName, objectKey)
	if err != nil {
		return nil, err
	}

	// FIXME: This does not work for SQS sources. The update needs to happen in the destination when writing.
	//        Since we now have the source id available in the Result this is now possible
	//        Because of mocks and globals that check the number of calls it is not an easy refactor to perform
	//        https://github.com/panther-labs/panther/issues/1500
	// If the incoming notification maps to a known source, update the source information
	if result != nil {
		now := time.Now() // No need to be UTC. We care about relative time
		deadline := lastEventReceived[result.IntegrationID].Add(statusUpdateFrequency)
		// if more than 'statusUpdateFrequency' time has passed, update status
		if now.After(deadline) {
			updateIntegrationStatus(result.IntegrationID, now)
			lastEventReceived[result.IntegrationID] = now
		}
	}

	return result, nil
}

// BuildClassifier builds a classifier for a source
func BuildClassifier(
	availableLogTypes []string,
	src *models.SourceIntegration,
	r pantherlog.ParserResolver,
) (classification.ClassifierAPI, error) {

	parserIndex := map[string]pantherlog.LogParser{}
	for _, logType := range availableLogTypes {
		parser, err := r.ResolveParser(context.TODO(), logType)
		if err != nil {
			return nil, errors.Wrapf(err, "could not resolve log type parser %q", logType)
		}
		if parser == nil {
			zap.L().Warn("unresolved log type parser", zap.String("logType", logType), zap.String("sourceId", src.IntegrationID))
			continue
		}
		parserIndex[logType] = newSourceFieldsParser(src.IntegrationID, src.IntegrationLabel, parser)
	}
	return classification.NewClassifier(parserIndex), nil
}

func newSourceFieldsParser(id, label string, parser pantherlog.LogParser) pantherlog.LogParser {
	return &sourceFieldsParser{
		Interface:   parser,
		SourceID:    id,
		SourceLabel: label,
	}
}

type sourceFieldsParser struct {
	parsers.Interface
	SourceID    string
	SourceLabel string
}

func (p *sourceFieldsParser) ParseLog(log string) ([]*pantherlog.Result, error) {
	results, err := p.Interface.ParseLog(log)
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		if result.EventIncludesPantherFields {
			if event, ok := result.Event.(parsers.PantherSourceSetter); ok {
				event.SetPantherSource(p.SourceID, p.SourceLabel)
				continue
			}
		}
		result.PantherSourceID = p.SourceID
		result.PantherSourceLabel = p.SourceLabel
	}
	return results, nil
}
