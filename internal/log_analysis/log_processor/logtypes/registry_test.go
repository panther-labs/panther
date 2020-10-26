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
	r := &Registry{}
	type T struct {
		Foo string `json:"foo" description:"foo field"`
	}
	require.Empty(t, r.Entries())
	require.Zero(t, r.Len())
	require.Panics(t, func() {
		MustFind(r, "Foo.Bar")
	})
	config := Config{
		Name:         "Foo.Bar",
		Description:  "Foo.Bar logs",
		ReferenceURL: "-",
		Schema:       T{},
		NewParser: parsers.FactoryFunc(func(params interface{}) (parsers.Interface, error) {
			return nil, nil
		}),
	}
	api := MustBuild(config)
	err := r.Register(api)
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
	configEmpty := Config{}
	configEmpty.Schema = struct{}{}
	nilEntry, err := configEmpty.BuildEntry()
	require.Error(t, err)
	require.Nil(t, nilEntry)

	// Ensure nil schemas don't pass
	configNil := Config{}
	configNil.Schema = nil
	nilEntry2, err := configNil.BuildEntry()
	require.Error(t, err)
	require.Nil(t, nilEntry2)

	require.Panics(t, func() {
		r.MustRegister(Must(api.String(), api))
	})
	require.True(t, r.Del(api.String()))
	require.NotPanics(t, func() {
		r.MustRegister(Must(api.String(), api))
	})

	require.Equal(t, api, r.Find("Foo.Bar"))
	require.NotPanics(t, func() {
		MustFind(r, "Foo.Bar")
	})
	require.Equal(t, []Entry{api}, r.Entries())
	require.Equal(t, []Entry{api}, AppendFind(nil, r, r.LogTypes()...))
	require.Equal(t, []Entry{api}, AppendFind(nil, r, "Foo.Bar"))
	require.Nil(t, AppendFind(nil, r, "Foo.Baz"))
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
