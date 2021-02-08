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
	"context"

	"github.com/pkg/errors"

	resourceTypesProvider "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

// Traverse a passed set of resource and return an error if any of them are not found in the current
// list of valid resource types
//
// CAVEAT: This method uses a hardcoded list of existing resource types. If this method is returning
// unexpected errors the hardcoded list may be missing new or modified resource types.
func validResourceTypeSet(checkResourceTypeSet []string) error {
	for _, writeResourceTypeEntry := range checkResourceTypeSet {
		if _, exists := resourceTypesProvider.ResourceTypes[writeResourceTypeEntry]; !exists {
			// Found a resource type that doesnt exist
			return errors.Errorf("%s", writeResourceTypeEntry)
		}
	}
	return nil
}

func getLogTypesSet() (map[string]struct{}, error) {
	availableLogTypes, err := logtypesAPI.ListAvailableLogTypes(context.TODO())
	if err != nil {
		return nil, err
	}
	logTypes := make(map[string]struct{})
	for _, logtype := range availableLogTypes.LogTypes {
		logTypes[logtype] = struct{}{}
	}
	return logTypes, nil
}

// Retrieve a set of log types from the logtypes api and validate every entry in the passed set
// is a value found in the logtypes-api returned set
//
// CAVEAT: This method will trigger a request to the log-types api EVERY time it is called.
func validateLogtypeSet(logtypes []string) error {
	logtypeSetMap, err := getLogTypesSet()
	if err != nil {
		return err
	}
	firstMissing := FirstSetItemNotInMapKeys(logtypes, logtypeSetMap)
	if len(firstMissing) > 0 {
		return errors.Errorf("%s", firstMissing)
	}
	return nil
}

// Returns the first set entry not found as a key in the searchMap
func FirstSetItemNotInMapKeys(itemSet []string, searchMap map[string]struct{}) string {
	for _, item := range itemSet {
		if _, found := searchMap[item]; !found {
			return item
		}
	}
	return ""
}
