package customlogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
)

func TestCheckSchemaUpdates(t *testing.T) {
	assert := require.New(t)
	assert.Error(CheckSchemaChange(&logschema.Change{
		Type: logschema.DeleteField,
		Path: []string{
			"Foo",
			"Bar",
			"Baz",
		},
		From: &logschema.FieldSchema{
			Name:     "Baz",
			Required: true,
			ValueSchema: logschema.ValueSchema{
				Type: logschema.TypeString,
			},
		},
	}))
	assert.Error(CheckSchemaChange(&logschema.Change{
		Type: logschema.UpdateValue,
		Path: []string{
			"Foo",
			"Bar",
			"Baz",
		},
		From: &logschema.ValueSchema{
			Type: logschema.TypeString,
		},
		To: &logschema.ValueSchema{
			Type: logschema.TypeObject,
		},
	}))
	assert.NoError(CheckSchemaChange(&logschema.Change{
		Type: logschema.UpdateFieldMeta,
		Path: []string{
			"Foo",
			"Bar",
			"Baz",
			"Description",
		},
		From: "Foo bar baz",
		To:   "Foo bar baz.",
	}))
	assert.NoError(CheckSchemaChange(&logschema.Change{
		Type: logschema.AddField,
		Path: []string{},
		To: &logschema.FieldSchema{
			Name:     "Bar",
			Required: true,
			ValueSchema: logschema.ValueSchema{
				Type: logschema.TypeString,
			},
		},
	}))
}
