package processor

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
	"testing"

	"github.com/stretchr/testify/assert"

	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
)

func TestIsSuppressed(t *testing.T) {
	resourceID := "prod.panther.us-west-2/device"

	assert.False(t, isSuppressed(resourceID, &analysismodels.EnabledPolicy{
		Suppressions: []string{},
	}))
	assert.False(t, isSuppressed(resourceID, &analysismodels.EnabledPolicy{
		Suppressions: []string{"prod", "prod.panther.us-west-2/device.*"},
	}))

	assert.True(t, isSuppressed(resourceID, &analysismodels.EnabledPolicy{
		Suppressions: []string{"*"},
	}))
	assert.True(t, isSuppressed(resourceID, &analysismodels.EnabledPolicy{
		Suppressions: []string{"prod.panther.*/device"},
	}))
	assert.True(t, isSuppressed(resourceID, &analysismodels.EnabledPolicy{
		Suppressions: []string{"*prod.panther.us-west-2/device*"},
	}))
	assert.True(t, isSuppressed(resourceID, &analysismodels.EnabledPolicy{
		Suppressions: []string{"not", "this", "one", "but", "here:", "*.us-west-2/*"},
	}))
}
