package transact

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
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/stretchr/testify/require"
)

func TestDDB(t *testing.T) {
	assert := require.New(t)
	e := expression.Expression{}
	assert.Nil(e.Condition())
	assert.Nil(e.Update())
	assert.Nil(e.Values())
	assert.Nil(e.Names())
	assert.Nil(e.Filter())
	assert.Nil(e.KeyCondition())
	assert.Nil(e.Projection())

	zeroCond := expression.ConditionBuilder{}
	eqCond := expression.Equal(expression.Name("foo"), expression.Value("bar"))
	assert.False(reflect.DeepEqual(zeroCond, eqCond))
	assert.False(reflect.DeepEqual(zeroCond, zeroCond.Not()))
}
