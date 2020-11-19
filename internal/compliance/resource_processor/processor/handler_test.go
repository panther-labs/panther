package processor

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

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"

	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	resourcemodels "github.com/panther-labs/panther/api/lambda/resources/models"
	"github.com/panther-labs/panther/internal/compliance/resource_processor/models"
)

func TestParseQueueMsgResource(t *testing.T) {
	resourceIn := &resourcemodels.Resource{
		Attributes: "{}",
		Type:       "Test.Resource",
	}
	body, _ := jsoniter.MarshalToString(resourceIn)

	resourceOut, policy, lookup := parseQueueMsg(body)
	assert.Equal(t, resourceIn, resourceOut)
	assert.Nil(t, policy)
	assert.Nil(t, lookup)
}

func TestParseQueueMsgPolicy(t *testing.T) {
	policyIn := &analysismodels.Policy{
		Body: "def policy(resource):\nreturn True",
		ID:   "TestPolicy",
	}
	body, _ := jsoniter.MarshalToString(policyIn)

	resource, policyOut, lookup := parseQueueMsg(body)
	assert.Nil(t, resource)
	assert.Equal(t, policyIn, policyOut)
	assert.Nil(t, lookup)
}

func TestParseQueueMsgLookup(t *testing.T) {
	lookupIn := &models.ResourceLookup{
		ID: "TestLookup",
	}
	body, _ := jsoniter.MarshalToString(lookupIn)
	resource, policy, lookupOut := parseQueueMsg(body)
	assert.Nil(t, resource)
	assert.Nil(t, policy)
	assert.Equal(t, &lookupIn.ID, lookupOut)
}

func TestParseQueueMsgMissingFields(t *testing.T) {
	resourceIn := &resourcemodels.Resource{
		Attributes: "{}",
		// Type is a required field
	}
	body, _ := jsoniter.MarshalToString(resourceIn)

	resourceOut, policy, lookup := parseQueueMsg(body)
	assert.Nil(t, resourceOut)
	assert.Nil(t, policy)
	assert.Nil(t, lookup)
}

func TestIsSuppressed(t *testing.T) {
	resourceID := "prod.panther.us-west-2/device"

	assert.False(t, isSuppressed(resourceID, analysismodels.Policy{
		Suppressions: []string{},
	}))
	assert.False(t, isSuppressed(resourceID, analysismodels.Policy{
		Suppressions: []string{"prod", "prod.panther.us-west-2/device.*"},
	}))

	assert.True(t, isSuppressed(resourceID, analysismodels.Policy{
		Suppressions: []string{"*"},
	}))
	assert.True(t, isSuppressed(resourceID, analysismodels.Policy{
		Suppressions: []string{"prod.panther.*/device"},
	}))
	assert.True(t, isSuppressed(resourceID, analysismodels.Policy{
		Suppressions: []string{"*prod.panther.us-west-2/device*"},
	}))
	assert.True(t, isSuppressed(resourceID, analysismodels.Policy{
		Suppressions: []string{"not", "this", "one", "but", "here:", "*.us-west-2/*"},
	}))
}
