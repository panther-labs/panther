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
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestProcessLine(t *testing.T) {
	schema, err := inferFromFile(nil, "./testdata/sample_1.jsonl")
	schema = schema.NonEmpty()
	assert.NoError(t, err)
	fd, err := ioutil.ReadFile("./testdata/schema_1.yml")
	assert.NoError(t, err)

	marshalled, err := yaml.Marshal(schema)
	assert.NoError(t, err)
	fmt.Println(string(marshalled))
	assert.YAMLEq(t, string(fd), string(marshalled))
}
