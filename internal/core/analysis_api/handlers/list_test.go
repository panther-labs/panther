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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

func TestPagePoliciesPageSize1(t *testing.T) {
	policies := []*models.PolicySummary{
		{ID: "a", OutputIds: []string{"output-1", "output-2"}},
		{ID: "b", OutputIds: []string{"output-3", "output-4"}},
		{ID: "c", OutputIds: []string{"output-5", "output-6"}},
		{ID: "d", OutputIds: []string{"output-7", "output-8"}}}
	result := pagePolicies(policies, 1, 1)
	expected := &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(4),
			TotalPages: aws.Int64(4),
		},
		Policies: []*models.PolicySummary{{ID: "a", OutputIds: []string{"output-1", "output-2"}}},
	}
	assert.Equal(t, expected, result)

	result = pagePolicies(policies, 1, 2)
	expected.Paging.ThisPage = aws.Int64(2)
	expected.Policies = []*models.PolicySummary{{ID: "b", OutputIds: []string{"output-3", "output-4"}}}
	assert.Equal(t, expected, result)

	result = pagePolicies(policies, 1, 3)
	expected.Paging.ThisPage = aws.Int64(3)
	expected.Policies = []*models.PolicySummary{{ID: "c", OutputIds: []string{"output-5", "output-6"}}}
	assert.Equal(t, expected, result)

	result = pagePolicies(policies, 1, 4)
	expected.Paging.ThisPage = aws.Int64(4)
	expected.Policies = []*models.PolicySummary{{ID: "d", OutputIds: []string{"output-7", "output-8"}}}
	assert.Equal(t, expected, result)
}

func TestPagePoliciesSinglePage(t *testing.T) {
	policies := []*models.PolicySummary{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	result := pagePolicies(policies, 25, 1)
	expected := &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(4),
			TotalPages: aws.Int64(1),
		},
		Policies: policies,
	}
	assert.Equal(t, expected, result)
}

func TestPagePoliciesPageOutOfBounds(t *testing.T) {
	policies := []*models.PolicySummary{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	result := pagePolicies(policies, 1, 10)
	expected := &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(10),
			TotalItems: aws.Int64(4),
			TotalPages: aws.Int64(4),
		},
		Policies: []*models.PolicySummary{}, // empty list - page out of bounds
	}
	assert.Equal(t, expected, result)
}
