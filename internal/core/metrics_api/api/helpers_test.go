package api

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

	"github.com/stretchr/testify/require"
)

func TestTotalValue(t *testing.T) {
	var values []float64
	var result float64
	values = []float64{1, 2, 1, 4, 5, -2}
	testValues := make([]*float64, len(values)-1)
	for i := 0; i < len(values)-1; i++ {
		testValues[i] = &values[i]
	}
	result = 13.0
	// test all positive values
	require.Equal(t, result, totalValue(testValues))
	// test negative value
	testValues[0] = &values[len(values)-1]
	result = 10.0
	require.Equal(t, result, totalValue(testValues))
}
