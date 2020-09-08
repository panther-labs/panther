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
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

func Lookup(id string) *models.SourceIntegration {
	return sourceCache.Find(id)
}

func BuildClassifier(src *models.SourceIntegration, r *logtypes.Registry) (classification.ClassifierAPI, error) {
	parsers := map[string]parsers.Interface{}
	for _, logType := range src.RequiredLogTypes() {
		entry := r.Get(logType)
		if entry == nil {
			return nil, errors.Errorf("invalid source log type %q", logType)
		}
		parser, err := entry.NewParser(nil)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to create %q parser", logType)
		}
		parsers[logType] = newSourceFieldsParser(src.IntegrationID, src.IntegrationLabel, parser)
	}
	return classification.NewClassifier(parsers), nil
}

func newSourceFieldsParser(id, label string, parser parsers.Interface) parsers.Interface {
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
