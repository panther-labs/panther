package forwarder

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

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

func TestCacheHttpError(t *testing.T) {
	t.Parallel()
	ruleClientMock := &testutils.GatewayapiMock{}
	cache := NewCache(ruleClientMock)

	ruleClientMock.On("Invoke", mock.Anything, mock.Anything).Return(http.StatusInternalServerError, nil).Once()
	rule, err := cache.Get("id", "version")
	assert.Error(t, err)
	assert.Nil(t, rule)
	ruleClientMock.AssertExpectations(t)
}

func TestCacheInvocationError(t *testing.T) {
	t.Parallel()
	ruleClientMock := &testutils.GatewayapiMock{}
	cache := NewCache(ruleClientMock)

	ruleClientMock.On("Invoke", mock.Anything, mock.Anything).Return(0, errors.New("test")).Once()
	rule, err := cache.Get("id", "version")
	assert.Error(t, err)
	assert.Nil(t, rule)
	ruleClientMock.AssertExpectations(t)
}

func TestCacheRuleRetrieval(t *testing.T) {
	t.Parallel()
	ruleClientMock := &testutils.GatewayapiMock{}
	cache := NewCache(ruleClientMock)

	expectedInput := &models.LambdaInput{
		GetRule: &models.GetRuleInput{ID: "id", VersionID: "version"},
	}
	ruleClientMock.On("Invoke", expectedInput, mock.Anything).Return(http.StatusOK, nil).Once()
	rule, err := cache.Get("id", "version")
	assert.NoError(t, err)
	assert.NotNil(t, rule)
	ruleClientMock.AssertExpectations(t)
}
