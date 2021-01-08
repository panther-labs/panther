package processor

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
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLambdaBaseEventName(t *testing.T) {
	baseName := "foo"
	var functionNames []string
	for _, version := range lambdaVersions {
		functionNames = append(functionNames, baseName+version)
	}
	// sort _opposite_  of what is optimal to prove stripping works
	sort.Strings(functionNames)
	for _, functionName := range functionNames {
		assert.Equal(t, baseName, getLambdaBaseEventName(functionName))
	}
}
