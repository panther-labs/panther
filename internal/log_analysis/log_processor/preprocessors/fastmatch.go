package preprocessors

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

	"github.com/panther-labs/panther/pkg/x/fastmatch"
)

// nolint:lll
type FastMatchConfig struct {
	Match        []string          `json:"match" yaml:"match" description:"Patterns to match in order"`
	SkipLines    int               `json:"skipLines,omitempty" yaml:"skipLines,omitempty" description:"Number of lines to skip at start of file"`
	SkipPrefix   string            `json:"skipPrefix,omitempty" yaml:"skipPrefix,omitempty" description:"Skip comment lines by prefix"`
	EmptyValues  []string          `json:"emptyValues,omitempty" yaml:"emptyValues,omitempty" description:"Placeholder value for empty or missing data"`
	ExpandFields map[string]string `json:"expandFields,omitempty" yaml:"expandFields,omitempty" description:"Add fields by text templates"`
	TrimSpace    bool              `json:"trimSpace,omitempty" yaml:"trimSpace,omitempty" description:"Trim space surrounding values"`
}

func (config FastMatchConfig) BuildPreprocessor() (Interface, error) {
	if len(config.Match) == 0 {
		return nil, errors.New("no match patterns")
	}
	patterns := make([]*fastmatch.Pattern, len(config.Match))
	for i, src := range config.Match {
		p, err := fastmatch.Compile(src)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to compile pattern #%d", i)
		}
		patterns[i] = p
	}
	return &matchTextPreprocessor{
		match: func(dst []string, src string) ([]string, error) {
			for _, p := range patterns {
				if matches, err := p.MatchString(dst, src); err == nil {
					return matches, nil
				}
			}
			return dst, errors.New("No match")
		},
		skipLines:    config.SkipLines,
		skipPrefix:   config.SkipPrefix,
		emptyValues:  config.EmptyValues,
		expandFields: compileFieldTemplates(config.ExpandFields),
		stream:       buildJSONStream(),
		trimSpace:    config.TrimSpace,
	}, nil
}
