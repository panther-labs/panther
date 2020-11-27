package gsuitelogs

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

	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
)

// nolint:lll
func TestParseGSuiteReports(t *testing.T) {
	logtesting.RunTestsFromYAML(t, LogTypes(), "./testdata/reports_tests.yml")
}

func TestReportsSamples(t *testing.T) {
	samples := testutil.MustReadFileJSONLines("testdata/reportslog_samples.jsonl")
	parser, err := LogTypes().Find(TypeReports).NewParser(nil)
	assert.NoError(t, err)
	for i, sample := range samples {
		_, err := parser.ParseLog(sample)
		assert.NoErrorf(t, err, "failed to parse line %d", i)
	}
}
