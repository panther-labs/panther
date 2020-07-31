package logtypes

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

func TestRegistry(t *testing.T) {
	r := Registry{}
	type T struct {
		Foo string `json:"foo" description:"foo field"`
	}
	logTypes := r.LogTypes()
	require.Empty(t, logTypes)
	require.Panics(t, func() {
		r.MustGet("Foo.Bar")
	})
	logTypeConfig := Config{
		Name:         "Foo.Bar",
		Description:  "Foo.Bar logs",
		ReferenceURL: "-",
		Schema:       T{},
		NewParser: func(params interface{}) (parsers.Interface, error) {
			return nil, nil
		},
	}
	api, err := r.Register(logTypeConfig)
	require.NoError(t, err)
	require.NotNil(t, api)
	require.Equal(t, Desc{
		Name:         "Foo.Bar",
		Description:  "Foo.Bar logs",
		ReferenceURL: "-",
	}, api.Describe())
	require.Equal(t, T{}, api.Schema())
	require.Equal(
		t,
		awsglue.NewGlueTableMetadata(models.LogData, "Foo.Bar", "Foo.Bar logs", awsglue.GlueTableHourly, T{}),
		api.GlueTableMeta(),
	)

	// Ensure invalid schemas don't pass
	configEmpty := logTypeConfig
	configEmpty.Schema = struct{}{}
	nilEntry, err := r.Register(configEmpty)
	require.Error(t, err)
	require.Nil(t, nilEntry)

	// Ensure nil schemas don't pass
	configNil := logTypeConfig
	configNil.Schema = nil
	nilEntry2, err := r.Register(configNil)
	require.Error(t, err)
	require.Nil(t, nilEntry2)

	entry, err := r.Register(logTypeConfig)
	require.Error(t, err)
	require.Equal(t, api, entry)
	require.Panics(t, func() {
		r.MustRegister(logTypeConfig)
	})
	require.True(t, r.Del(logTypeConfig.Name))
	require.NotPanics(t, func() {
		api = r.MustRegister(logTypeConfig)
	})

	getAPI := r.Get("Foo.Bar")
	require.Equal(t, api, getAPI)
	require.NotPanics(t, func() {
		r.MustGet("Foo.Bar")
	})
	require.Equal(t, []Entry{api}, r.Entries())
	require.Equal(t, []Entry{api}, r.Entries("Foo.Bar"))
	require.Equal(t, []Entry{}, r.Entries("Foo.Baz"))
	require.Equal(t, []string{"Foo.Bar"}, r.LogTypes())
	require.NotNil(t, DefaultRegistry())
	require.NoError(t, Register(logTypeConfig))
	globalEntry := DefaultRegistry().Get(logTypeConfig.Name)
	require.NotNil(t, globalEntry)
	require.Error(t, Register(logTypeConfig))
	require.Panics(t, func() {
		MustRegister(logTypeConfig)
	})
	require.True(t, DefaultRegistry().Del(logTypeConfig.Name))
	require.NotPanics(t, func() {
		MustRegister(logTypeConfig)
	})
}

func TestDesc(t *testing.T) {
	require.Error(t, (&Desc{}).Validate())
	require.Error(t, (&Desc{
		Name: "Foo",
	}).Validate())
	require.Error(t, (&Desc{
		Name:        "Foo",
		Description: "Bar",
	}).Validate())
	require.Error(t, (&Desc{
		Name:         "Foo",
		Description:  "Bar",
		ReferenceURL: "invalid url",
	}).Validate())
	require.Error(t, (&Desc{
		Name:         "Foo",
		ReferenceURL: "http://example.org",
	}).Validate())
	require.Error(t, (&Desc{
		Name:         "Foo",
		ReferenceURL: "-",
	}).Validate())
	require.NoError(t, (&Desc{
		Name:         "Foo",
		Description:  "Foo bar",
		ReferenceURL: "-",
	}).Validate())
	require.NoError(t, (&Desc{
		Name:         "Foo",
		Description:  "Foo bar",
		ReferenceURL: "https://example.org",
	}).Validate())
}
