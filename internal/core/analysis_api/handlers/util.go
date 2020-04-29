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
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	// Enum which indicates what kind of change took place
	noChange    = iota
	newItem     = iota
	updatedItem = iota
)

var (
	// Custom errors make it easy for callers to identify which error was triggered
	errNotExists = errors.New("policy/rule does not exist")
	errExists    = errors.New("policy/rule already exists")
	errWrongType = errors.New("trying to replace a rule with a policy (or vice versa)")
)

// Convert a validation error into a 400 proxy response.
func badRequest(err error) *events.APIGatewayProxyResponse {
	return failedRequest(err.Error(), http.StatusBadRequest)
}

func failedRequest(message string, status int) *events.APIGatewayProxyResponse {
	errModel := &models.Error{Message: aws.String(message)}
	return gatewayapi.MarshalResponse(errModel, status)
}

// Convert a set of strings to a set of unique lowercased strings
func lowerSet(set []string) []string {
	seen := make(map[string]bool, len(set))
	result := make([]string, 0, len(set))

	for _, item := range set {
		lower := strings.ToLower(item)
		if !seen[lower] {
			result = append(result, lower)
			seen[lower] = true
		}
	}

	return result
}

// Integer min function
func intMin(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// Compute the set difference - items in the first set but not the second
func setDifference(first, second []string) (result []string) {
	secondMap := make(map[string]bool, len(second))
	for _, x := range second {
		secondMap[x] = true
	}

	for _, x := range first {
		if !secondMap[x] {
			result = append(result, x)
		}
	}

	return
}

// Returns true if the two string slices have the same unique elements in any order
func setEquality(first, second []string) bool {
	firstMap := make(map[string]bool, len(first))
	for _, x := range first {
		firstMap[x] = true
	}

	secondMap := make(map[string]bool, len(second))
	for _, x := range second {
		secondMap[x] = true
	}

	if len(firstMap) != len(secondMap) {
		return false
	}

	for x := range firstMap {
		if !secondMap[x] {
			return false
		}
	}

	return true
}

// Create/update a policy or rule.
//
// The following fields are set automatically (need not be set by the caller):
//     CreatedAt, CreatedBy, LastModified, LastModifiedBy, VersionID
//
// To update an existing item,              mustExist = aws.Bool(true)
// To create a new item (with a unique ID), mustExist = aws.Bool(false)
// To allow either an update or a create,   mustExist = nil (neither)
//
// The first return value indicates what kind of change took place (none, new item, updated item).
func writeItem(item *tableItem, userID models.UserID, mustExist *bool) (int, error) {
	oldItem, err := dynamoGet(item.ID, true)
	changeType := noChange
	if err != nil {
		return changeType, err
	}

	if mustExist != nil {
		if *mustExist && oldItem == nil {
			return changeType, errNotExists // item should exist but does not (update)
		}
		if !*mustExist && oldItem != nil {
			return changeType, errExists // item exists but should not (create)
		}
	}

	if oldItem == nil {
		item.CreatedAt = models.ModifyTime(time.Now())
		item.CreatedBy = userID
		changeType = newItem
	} else {
		if oldItem.Type != item.Type {
			return changeType, errWrongType
		}

		item.CreatedAt = oldItem.CreatedAt
		item.CreatedBy = oldItem.CreatedBy
		if itemUpdated(oldItem, item) {
			changeType = updatedItem
		}
	}

	item.LastModified = models.ModifyTime(time.Now())
	item.LastModifiedBy = userID

	// Write to S3 first so we can get the versionID
	if err := s3Upload(item); err != nil {
		return changeType, err
	}

	// Write to Dynamo (with version ID)
	if err := dynamoPut(item); err != nil {
		return changeType, err
	}

	if item.Type == typeRule {
		return changeType, nil
	}

	if item.Type == typeGlobal {
		// When policies and rules are also managed by globals, this can be moved out of the if statement,
		// although at that point it may be desirable to move this to the caller function so as to only make the call
		// once for BulkUpload.
		return changeType, updateLayer(item.Type)
	}

	// Updated policies may require changes to the compliance status.
	if err := updateComplianceStatus(oldItem, item); err != nil {
		zap.L().Error("item update successful but failed to update compliance status", zap.Error(err))
		// A failure here means we couldn't update the compliance status right now, but it will
		// still be updated on the next daily scan / resource change, so we don't need to mark the
		// entire API call as a failure.
	}
	return changeType, nil
}

// itemUpdated checks if ANY field has been changed between the old and new item. Only used to inform users whether the
// result of a BulkUpload operation actually changed something or not.
//
// DO NOT use this for situations the items MUST be exactly equal, this is a "good enough" approximation for the
// purpose it serves, which is informing users that their bulk operation did or did not change something.
func itemUpdated(oldItem, newItem *tableItem) bool {
	itemsEqual := oldItem.AutoRemediationID == newItem.AutoRemediationID && oldItem.Body == newItem.Body &&
		oldItem.Description == newItem.Description && oldItem.DisplayName == newItem.DisplayName &&
		oldItem.Enabled == newItem.Enabled && oldItem.Reference == newItem.Reference &&
		oldItem.Runbook == newItem.Runbook && oldItem.Severity == newItem.Severity &&
		oldItem.DedupPeriodMinutes == newItem.DedupPeriodMinutes &&
		setEquality(oldItem.ResourceTypes, newItem.ResourceTypes) &&
		setEquality(oldItem.Suppressions, newItem.Suppressions) && setEquality(oldItem.Tags, newItem.Tags) &&
		len(oldItem.AutoRemediationParameters) == len(newItem.AutoRemediationParameters) &&
		len(oldItem.Tests) == len(newItem.Tests)

	if !itemsEqual {
		return true
	}

	// Check AutoRemediationParameters for equality (we can't compare maps with ==)
	for key, value := range oldItem.AutoRemediationParameters {
		if newValue, ok := newItem.AutoRemediationParameters[key]; !ok || newValue != value {
			// Something changed, so this item has been updated
			return true
		}
	}
	// Check Tests for equality
	oldTests := make(map[models.TestName]*models.UnitTest)
	for _, test := range oldItem.Tests {
		oldTests[test.Name] = test
	}
	for _, newTest := range newItem.Tests {
		oldTest, ok := oldTests[newTest.Name]
		// First check if the meta data of the test is equal
		if !ok || oldTest.ResourceType != newTest.ResourceType || oldTest.ExpectedResult != newTest.ExpectedResult {
			// Something changed, so this item has been updated
			return true
		}

		// The resource is a string that consists of valid JSON, and represents a test case. At some point in the
		// processing pipeline, it gets converted into a struct then back into a JSON string. Because of this, the
		// resource that the user uploads and the actual resource stored in dynamo may be different string
		// representations of the same JSON object. In order to compare them then, we have to unmarshal them into a
		// consistent format.
		var oldResource, newResource map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(oldTest.Resource), &oldResource); err != nil {
			// It is possible someone uploaded bad JSON in this test, it is not the responsibility of this test to
			// report that. Just do a raw string comparison.
			if oldTest.Resource != newTest.Resource {
				return true
			}
			continue
		}
		if err := jsoniter.UnmarshalFromString(string(newTest.Resource), &newResource); err != nil {
			if oldTest.Resource != newTest.Resource {
				return true
			}
			continue
		}

		if !reflect.DeepEqual(oldResource, newResource) {
			return true
		}
	}

	// If they're the same, the item wasn't really updated
	return !itemsEqual
}

// Sort a slice of strings ignoring case when possible
func sortCaseInsensitive(values []string) {
	sort.Slice(values, func(i, j int) bool {
		first, second := strings.ToLower(values[i]), strings.ToLower(values[j])
		if first == second {
			// Same lowercase value, fallback to default sort
			return values[i] < values[j]
		}

		// Compare the lowercase version of the strings
		return first < second
	})
}
