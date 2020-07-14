package cache

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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

var cacheFuncReturnValue = map[string]interface{}{
	"key": "value",
}

func TestRetrieveValue(t *testing.T) {
	timesCalled := 0
	refreshFunc := func() (map[string]interface{}, error) {
		timesCalled++
		return cacheFuncReturnValue, nil
	}
	cache := New(refreshFunc)
	value, ok := cache.Get("key")
	assert.Equal(t, "value", value)
	assert.True(t, ok)
	assert.Equal(t, 1, timesCalled)
}

func TestRetrieveDoesNotExist(t *testing.T) {
	timesCalled := 0
	refreshFunc := func() (map[string]interface{}, error) {
		timesCalled++
		return cacheFuncReturnValue, nil
	}
	cache := New(refreshFunc)
	value, ok := cache.Get("key-does-not-exist")
	assert.False(t, ok)
	assert.Nil(t, value)
	assert.Equal(t, 1, timesCalled)
}

func TestRetrieveReturnsError(t *testing.T) {
	timesCalled := 0
	refreshFunc := func() (map[string]interface{}, error) {
		timesCalled++
		return cacheFuncReturnValue, errors.New("error")
	}
	cache := New(refreshFunc)
	value, ok := cache.Get("key-does-not-exist")
	assert.False(t, ok)
	assert.Nil(t, value)
	assert.Equal(t, 1, timesCalled)
}

func TestRetrieveValueShouldRespectMinimumInterval(t *testing.T) {
	timesCalled := 0
	refreshFunc := func() (map[string]interface{}, error) {
		timesCalled++
		return cacheFuncReturnValue, nil
	}
	cache := New(refreshFunc)
	value, ok := cache.Get("key")
	assert.Equal(t, "value", value)
	assert.True(t, ok)
	// This should not trigger refreshing of the cache
	value, ok = cache.Get("new-key")
	assert.Nil(t, value)
	assert.False(t, ok)
	assert.Equal(t, 1, timesCalled)
}
