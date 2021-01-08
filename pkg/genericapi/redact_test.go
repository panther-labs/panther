package genericapi

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

func TestRedactedInputFlat(t *testing.T) {
	type flatInput struct {
		Count       int64   `json:"count"`
		CountSecret int64   `genericapi:"redact" json:"countSecret"`
		Name        *string `json:"name"`
		NameSecret  *string `genericapi:"redact" json:"nameSecret"`
	}

	result := redactedInput(reflect.ValueOf(flatInput{}))
	expected := map[string]interface{}{
		"count":       int64(0),
		"countSecret": "(redacted int64)",
		"name":        nil,
		"nameSecret":  nil,
	}
	assert.Equal(t, expected, result)

	result = redactedInput(reflect.ValueOf(&flatInput{
		Count:       123,
		CountSecret: 123,
		Name:        aws.String("panther"),
		NameSecret:  aws.String("panther"),
	}))
	expected = map[string]interface{}{
		"count":       int64(123),
		"countSecret": "(redacted int64)",
		"name":        "panther",
		"nameSecret":  "(redacted string len=7)",
	}
	assert.Equal(t, expected, result)
}

func TestRedactedInputNested(t *testing.T) {
	type embedding struct {
		Count     *int       `json:"count"`
		Embedding *embedding `json:"embedding"`
		Secret    *string    `genericapi:"redact" json:"secret"`
	}

	type config struct {
		Name *string `json:"name"`
	}

	type nestedInput struct {
		*config `genericapi:"redact"`
		embedding
	}

	result := redactedInput(reflect.ValueOf(nestedInput{}))
	expected := map[string]interface{}{
		"config": nil,
		"embedding": map[string]interface{}{
			"count":     nil,
			"embedding": nil,
			"secret":    nil,
		},
	}
	assert.Equal(t, expected, result)

	result = redactedInput(reflect.ValueOf(nestedInput{
		config: &config{Name: aws.String("panther")},
		embedding: embedding{
			Count: aws.Int(123),
			Embedding: &embedding{
				Embedding: &embedding{Secret: aws.String("super-secret")},
			},
			Secret: aws.String("super-secret"),
		},
	}))
	expected = map[string]interface{}{
		"config": "(redacted struct)",
		"embedding": map[string]interface{}{
			"count": 123,
			"embedding": map[string]interface{}{
				"count": nil,
				"embedding": map[string]interface{}{
					"count":     nil,
					"embedding": nil,
					"secret":    "(redacted string len=12)",
				},
				"secret": nil,
			},
			"secret": "(redacted string len=12)",
		},
	}
	assert.Equal(t, expected, result)
}

func TestRedactedInputArraySlice(t *testing.T) {
	type config struct {
		Name   *string `json:"name"`
		Secret *string `genericapi:"redact" json:"secret"`
	}

	type sliceInput struct {
		Configs []*config `json:"configs"`
		Secrets []*string `genericapi:"redact" json:"secrets"`
		Tags    []*string `json:"tags"`
		Tuple   [2]int    `json:"tuple"`
	}

	result := redactedInput(reflect.ValueOf(sliceInput{Tags: []*string{}}))
	expected := map[string]interface{}{
		"configs": ([]interface{})(nil), // null
		"secrets": nil,                  // null
		"tags":    []interface{}{},      // empty list []
		"tuple":   []interface{}{0, 0},  // [0, 0]
	}
	assert.Equal(t, expected, result)

	result = redactedInput(reflect.ValueOf(sliceInput{
		Configs: []*config{
			{
				Name:   aws.String("panther"),
				Secret: aws.String("super-secret"),
			},
			{
				Name:   aws.String("panther2"),
				Secret: aws.String("short"),
			},
		},
		Secrets: []*string{aws.String("super-secret")},
		Tags:    []*string{aws.String("tag1"), nil, aws.String("tag2")},
		Tuple:   [2]int{1, 2},
	}))
	expected = map[string]interface{}{
		"configs": []interface{}{
			map[string]interface{}{
				"name":   "panther",
				"secret": "(redacted string len=12)",
			},
			map[string]interface{}{
				"name":   "panther2",
				"secret": "(redacted string len=5)",
			},
		},
		"secrets": "(redacted slice len=1)",
		"tags":    []interface{}{"tag1", nil, "tag2"},
		"tuple":   []interface{}{1, 2},
	}
	assert.Equal(t, expected, result)
}

func TestRedactedInputMap(t *testing.T) {
	type config struct {
		Name   *string `json:"name"`
		Secret *string `genericapi:"redact" json:"secret"`
	}

	type mapInput struct {
		Configs map[string]*config `json:"configs"`
		Secrets map[int]bool       `genericapi:"redact" json:"secrets"`
	}

	result := redactedInput(reflect.ValueOf(mapInput{}))
	expected := map[string]interface{}{
		"configs": (map[interface{}]interface{})(nil),
		"secrets": (interface{})(nil),
	}
	assert.Equal(t, expected, result)

	result = redactedInput(reflect.ValueOf(mapInput{
		Configs: map[string]*config{
			"panther-labs": {
				Name:   aws.String("panther"),
				Secret: aws.String("labs"),
			},
			"someone-else": nil,
		},
		Secrets: map[int]bool{0: false, 1: false, 2: true, 3: true},
	}))
	expected = map[string]interface{}{
		"configs": map[interface{}]interface{}{
			"panther-labs": map[string]interface{}{
				"name":   "panther",
				"secret": "(redacted string len=4)",
			},
			"someone-else": nil,
		},
		"secrets": "(redacted map len=4)",
	}
	assert.Equal(t, expected, result)
}

func TestRedactedPrivateFields(t *testing.T) {
	type config struct {
		Timestamp   *time.Time
		PublicName  *string
		privateName *string
	}

	now := time.Now()
	result := redactedInput(reflect.ValueOf(&config{
		Timestamp:   aws.Time(now),
		PublicName:  aws.String("panther"),
		privateName: aws.String("labs"),
	}))

	expected := map[string]interface{}{
		"PublicName": "panther",
		"Timestamp":  now.Format(time.RFC3339),
	}
	assert.Equal(t, expected, result)
}
