package handlers

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
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

func TestLowerSet(t *testing.T) {
	result := lowerSet([]string{"AWS", "aws", "CIS", "cis", "Panther"})
	sort.Strings(result)
	assert.Equal(t, []string{"aws", "cis", "panther"}, result)
}

func TestIntMin(t *testing.T) {
	assert.Equal(t, -2, intMin(-2, 0))
	assert.Equal(t, 0, intMin(0, 0))
	assert.Equal(t, 5, intMin(10, 5))
}

func TestSetDifference(t *testing.T) {
	assert.Empty(t, setDifference([]string{}, []string{}))
	assert.Empty(t, setDifference([]string{"a", "b", "c"}, []string{"c", "a", "b"}))
	assert.Equal(t, []string{"a", "b"}, setDifference([]string{"a", "b"}, nil))
	assert.Empty(t, setDifference(nil, []string{"a", "b"}))
	assert.Equal(t, []string{"panther", "labs"},
		setDifference([]string{"panther", "labs", "inc"}, []string{"inc", "runpanther.io"}))
}

func TestSetEquality(t *testing.T) {
	assert.True(t, setEquality(nil, []string{}))
	assert.True(t, setEquality([]string{"panther", "labs", "inc"}, []string{"inc", "labs", "panther"}))
	assert.False(t, setEquality([]string{"panther"}, []string{"panther", "labs"}))
	assert.False(t, setEquality([]string{"panther", "labs"}, []string{"panther", "inc"}))
}

func TestPoliciesEqual(t *testing.T) {
	first := &tableItem{
		Body:          "def policy(resource): return True",
		ID:            "My:Favorite:Policy",
		ResourceTypes: nil,
		OutputIDs:     []string{"My Slack Channel", "Custom Webhook"},
		Tags:          []string{"AWS", "pci", "S3"},
		Tests: []models.UnitTest{
			{
				ExpectedResult: true,
				Resource:       `{"first": "a", "second": "b", "third": "c"}`,
			},
		},

		// These fields shouldn't matter for equality testing
		CreatedAt: time.Now(),
		CreatedBy: "austin",
		VersionID: "version-the-first",
		LowerID:   "my:favorite:policy",
		LowerTags: []string{"aws", "pci", "s3"},
	}
	second := &tableItem{
		Body:          first.Body,
		ID:            first.ID,
		ResourceTypes: []string{},
		OutputIDs:     []string{"Custom Webhook", "My Slack Channel"}, // same destinations, different order
		Tags:          []string{"pci", "S3", "AWS"},                   // same tags, different order
		Tests: []models.UnitTest{
			{
				ExpectedResult: true,
				Resource:       `{"second":"b","first":"a","third":"c"}`, // same resource, different order
			},
		},
	}
	equal, err := policiesEqual(first, second)
	assert.True(t, equal)
	assert.NoError(t, err)

	second.Body = "def policy(resource): return False"
	equal, err = policiesEqual(first, second)
	assert.False(t, equal)
	assert.NoError(t, err)
}

func TestSortCaseInsensitive(t *testing.T) {
	input := []string{"AWS.EC2.VPC", "AWS.EC2.Volume"}
	sortCaseInsensitive(input)
	assert.Equal(t, []string{"AWS.EC2.Volume", "AWS.EC2.VPC"}, input)

	// Sort by case if lowercase versions are equal
	input = []string{"panther", "Panther", "Panna Cotta", "panna cotta"}
	sortCaseInsensitive(input)
	expected := []string{"Panna Cotta", "panna cotta", "Panther", "panther"}
	assert.Equal(t, expected, input)
}
