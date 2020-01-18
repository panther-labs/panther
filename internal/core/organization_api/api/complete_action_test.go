package api

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/organization/models"
)

func (m *mockTable) AddActions(actions []*models.Action) (*models.Organization, error) {
	args := m.Called(actions)
	return args.Get(0).(*models.Organization), args.Error(1)
}

func TestCompleteActionError(t *testing.T) {
	m := &mockTable{}
	m.On("AddActions", mock.Anything, mock.Anything).Return(
		(*models.Organization)(nil), errors.New(""))
	orgTable = m

	action := models.VisitedOnboardingFlow
	result, err := (API{}).CompleteAction(&models.CompleteActionInput{
		CompletedActions: []*models.Action{&action},
	})
	m.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestCompleteAction(t *testing.T) {
	m := &mockTable{}
	action := models.VisitedOnboardingFlow
	output := &models.Organization{
		CompletedActions: []*models.Action{&action},
	}
	m.On("AddActions", mock.Anything, mock.Anything).Return(output, nil)
	orgTable = m

	result, err := (API{}).CompleteAction(&models.CompleteActionInput{
		CompletedActions: []*models.Action{&action},
	})
	m.AssertExpectations(t)
	assert.Equal(t, &models.CompleteActionOutput{CompletedActions: output.CompletedActions}, result)
	assert.NoError(t, err)
}
