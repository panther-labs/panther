package models

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
)

var mockID = aws.String("39c78f99-0149-482e-8f7b-090d75f253bf")

func TestUpdateUserNoFields(t *testing.T) {
	assert.NotNil(t, Validator().Struct(&UpdateUserInput{ID: mockID}))
}

func TestUpdateUserBlankField(t *testing.T) {
	assert.Error(t, Validator().Struct(&UpdateUserInput{
		ID:        mockID,
		GivenName: aws.String(""),
	}))
}

func TestUpdateUserOneField(t *testing.T) {
	assert.NoError(t, Validator().Struct(&UpdateUserInput{
		RequesterID: mockID,
		ID:          mockID,
		GivenName:   aws.String("panther"),
	}))
}

func TestUpdateUserAllFields(t *testing.T) {
	assert.NoError(t, Validator().Struct(&UpdateUserInput{
		RequesterID: mockID,
		ID:          mockID,
		GivenName:   aws.String("given-name"),
		FamilyName:  aws.String("family-name"),
	}))
}
