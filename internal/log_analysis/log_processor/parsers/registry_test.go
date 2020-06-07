package parsers

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

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

func TestNewRegistry(t *testing.T) {
	r := Registry{}
	logTypes := r.LogTypes()
	require.Empty(t, logTypes)
	require.Panics(t, func() {
		r.MustGet("Foo.Bar")
	})
	api, err := r.Register(LogTypeConfig{
		Name:         "Foo.Bar",
		Description:  "Foo.Bar logs",
		ReferenceURL: "-",
		Schema:       struct{}{},
		NewParser: func(params interface{}) pantherlog.LogParser {
			return nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, api)
	require.Equal(t, Desc{
		Name:         "Foo.Bar",
		Description:  "Foo.Bar logs",
		ReferenceURL: "-",
	}, api.Describe())
	require.Equal(t, struct{}{}, api.Schema())
	require.Equal(
		t,
		awsglue.NewGlueTableMetadata(models.LogData, "Foo.Bar", "Foo.Bar logs", awsglue.GlueTableHourly, struct{}{}),
		api.GlueTableMeta(),
	)
	getAPI := r.Get("Foo.Bar")
	require.Equal(t, api, getAPI)
	require.Equal(t, []LogTypeEntry{api}, r.Entries())
	require.Equal(t, []LogTypeEntry{api}, r.Entries("Foo.Bar"))
	require.Equal(t, []LogTypeEntry{}, r.Entries("Foo.Baz"))
	require.Equal(t, []string{"Foo.Bar"}, r.LogTypes())
}
