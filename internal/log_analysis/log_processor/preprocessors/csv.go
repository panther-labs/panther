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
	"encoding/csv"
	"strings"

	"github.com/pkg/errors"
)

// nolint:lll
type CSVMatchConfig struct {
	Delimiter string `json:"delimiter" yaml:"delimiter" description:"Delimiter to split the CSV file."`
	// Setting this to true will use column names from the first line unless `columns` field is set as well, overriding names in the header
	HasHeader    bool              `json:"hasHeader,omitempty" yaml:"hasHeader,omitempty" description:"Use first row to derive column names"`
	TrimSpace    bool              `json:"trimSpace,omitempty" yaml:"trimSpace,omitempty" description:"Trim space surrounding values"`
	Columns      []string          `json:"columns,omitempty" yaml:"columns,omitempty" description:"Header to use for this CSV file. This overrides column names if 'hasHeader' is true"`
	SkipPrefix   string            `json:"skipPrefix,omitempty" yaml:"skipPrefix,omitempty" description:"Skip comment lines by prefix"`
	EmptyValues  []string          `json:"emptyValues,omitempty" yaml:"emptyValues,omitempty" description:"Placeholder value for empty or missing data"`
	ExpandFields map[string]string `json:"expandFields,omitempty" yaml:"expandFields,omitempty" description:"Add fields by text templates"`
}

const defaultCSVDelimiter rune = ','

func (config CSVMatchConfig) BuildPreprocessor() (Interface, error) {
	var columns []string
	if len(config.Columns) > 0 {
		columns = config.Columns
	}
	if columns == nil && !config.HasHeader {
		return nil, errors.New("No columns for headerless CSV")
	}
	delimiter := defaultCSVDelimiter
	if d := []rune(config.Delimiter); len(d) > 0 {
		delimiter = d[0]
	}
	skipLines := 0
	// If user overrides column names we just skip the header
	if config.HasHeader && columns != nil {
		skipLines = 1
	}

	r := strings.NewReader("")
	csvReader := csv.NewReader(r)
	// Avoid allocations
	csvReader.ReuseRecord = true
	// Handle quotes lazily
	csvReader.LazyQuotes = true
	csvReader.Comma = delimiter
	var p *csvPreprocessor // Pre-define p so we can reference it in match
	p = &csvPreprocessor{
		logReader:      r,
		csvReader:      csvReader,
		columns:        columns,
		commentsPrefix: config.SkipPrefix,
		matchTextPreprocessor: matchTextPreprocessor{
			skipPrefix:  config.SkipPrefix,
			skipLines:   skipLines,
			emptyValues: config.EmptyValues,
			stream:      buildJSONStream(),
			match: func(dst []string, src string) ([]string, error) {
				p.logReader.Reset(src)
				values, err := csvReader.Read()
				if err != nil {
					return dst, err
				}
				// It is important to use p.columns here so we can use column names from header
				return zipFields(dst, p.columns, values), nil
			},
			expandFields: compileFieldTemplates(config.ExpandFields),
		},
	}
	return p, nil
}

type csvPreprocessor struct {
	logReader      *strings.Reader
	commentsPrefix string
	csvReader      *csv.Reader
	columns        []string
	matchTextPreprocessor
}

func (p *csvPreprocessor) PreProcessLog(log string) (string, error) {
	if p.columns == nil {
		p.logReader.Reset(log)
		columns, err := p.csvReader.Read()
		if err != nil {
			return "", err
		}
		p.columns = make([]string, len(columns))
		// Set number of columns
		p.csvReader.FieldsPerRecord = copy(p.columns, columns)
		return "", nil
	}
	return p.matchTextPreprocessor.PreProcessLog(log)
}

func zipFields(dst, names, values []string) []string {
	for i, name := range names {
		var value string
		if 0 <= i && i < len(values) {
			value = values[i]
		}
		dst = append(dst, name, value)
	}
	return dst
}
