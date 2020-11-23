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

	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

func TestPagePoliciesPageSize1(t *testing.T) {
	items := []tableItem{
		{ID: "a", OutputIDs: []string{"output-1", "output-2"}},
		{ID: "b", OutputIDs: []string{"output-3", "output-4"}},
		{ID: "c", OutputIDs: []string{"output-5", "output-6"}},
		{ID: "d", OutputIDs: []string{"output-7", "output-8"}}}
	paging, truncation := pageItems(items, 1, 1)

	assert.Equal(t, models.Paging{ThisPage: 1, TotalItems: 4, TotalPages: 4}, paging)
	assert.Equal(t, []tableItem{items[0]}, truncation)

	paging, truncation = pageItems(items, 2, 1)
	assert.Equal(t, models.Paging{ThisPage: 2, TotalItems: 4, TotalPages: 4}, paging)
	assert.Equal(t, []tableItem{items[1]}, truncation)

	paging, truncation = pageItems(items, 3, 1)
	assert.Equal(t, models.Paging{ThisPage: 3, TotalItems: 4, TotalPages: 4}, paging)
	assert.Equal(t, []tableItem{items[2]}, truncation)

	paging, truncation = pageItems(items, 4, 1)
	assert.Equal(t, models.Paging{ThisPage: 4, TotalItems: 4, TotalPages: 4}, paging)
	assert.Equal(t, []tableItem{items[3]}, truncation)
}

func TestPagePoliciesSinglePage(t *testing.T) {
	items := []tableItem{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	paging, truncation := pageItems(items, 1, 25)
	assert.Equal(t, models.Paging{ThisPage: 1, TotalItems: 4, TotalPages: 1}, paging)
	assert.Equal(t, truncation, items)
}

func TestPagePoliciesPageOutOfBounds(t *testing.T) {
	items := []tableItem{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	paging, truncation := pageItems(items, 10, 1)
	assert.Equal(t, models.Paging{ThisPage: 10, TotalItems: 4, TotalPages: 4}, paging)
	assert.Equal(t, truncation, []tableItem{}) // empty list - page out of bounds
}
