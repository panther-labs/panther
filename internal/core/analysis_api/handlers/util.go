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
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
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
		changeType = updatedItem
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
