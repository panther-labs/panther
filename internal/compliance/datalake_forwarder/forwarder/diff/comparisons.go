package diff

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
	"strconv"

	"github.com/tidwall/gjson"
)

// NOTE: it would be wise to use a dedicated lib for this such as https://github.com/r3labs/diff

type Diff struct {
	From interface{} `json:"from"`
	To   interface{} `json:"to"`
}
type Changelog map[string]Diff

// CompJsons compares two JSON strings, and returns a map of paths to changed fields to a tuple of
// the old and new value of that field
func CompJsons(left, right []byte) (map[string]Diff, error) {
	return compGJsons(gjson.ParseBytes(left), gjson.ParseBytes(right), "")
}

// nolint: funlen
// compGJsons does the recursive work of comparing each element in one gsjon result with each
// corresponding element in the other gjson result
func compGJsons(left, right gjson.Result, path string) (map[string]Diff, error) {
	// If the types are different, there's nothing to compare so just return straight up
	if left.Type != right.Type {
		return map[string]Diff{
			path: {
				From: gjsonResultToInterface(left),
				To:   gjsonResultToInterface(right),
			},
		}, nil
	}

	// If the results are objects, we need to iterate over each key in each object and compare it to
	// the corresponding key (if any) in the other object
	if left.IsObject() {
		var err error
		// mergedNestedDiffs will be used to aggregate the nested changes of each key
		mergedNestedDiffs := make(map[string]Diff)
		left.ForEach(func(key, leftValue gjson.Result) bool {
			rightValue := right.Get(key.String())
			var nestedDiffs map[string]Diff
			// Handle top level keys as a special case
			newPath := path + "." + key.String()
			if path == "" {
				newPath = key.String()
			}
			nestedDiffs, err = compGJsons(leftValue, rightValue, newPath)
			if err != nil {
				return false
			}
			for nestedKey, nestedValue := range nestedDiffs {
				mergedNestedDiffs[nestedKey] = nestedValue
			}
			return true
		})
		// Now check for any keys on the right that are not present on the left
		right.ForEach(func(key, rightValue gjson.Result) bool {
			leftValue := left.Get(key.String())
			// No need to re-process if the key does exist on the left
			if leftValue.Exists() {
				return true
			}
			var nestedDiffs map[string]Diff
			newPath := path + "." + key.String()
			// Same check for top level keys
			if path == "" {
				newPath = key.String()
			}
			nestedDiffs, err = compGJsons(leftValue, rightValue, newPath)
			if err != nil {
				return false
			}
			for nestedKey, nestedValue := range nestedDiffs {
				mergedNestedDiffs[nestedKey] = nestedValue
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		if len(mergedNestedDiffs) == 0 {
			return nil, nil
		}
		return mergedNestedDiffs, nil
	}

	// If the results are arrays, iterate through each element in each array and compare it to the
	// element (if any) at the corresponding index in the other array
	if left.IsArray() {
		leftArray, rightArray := left.Array(), right.Array()
		iter := 0
		leftLen, rightLen := len(leftArray), len(rightArray)
		mergedNestedDiffs := make(map[string]Diff)
		for {
			// If we still have room in both arrays, do the comparison
			if iter < leftLen && iter < rightLen {
				nestedDiff, err := compGJsons(leftArray[iter], rightArray[iter], path+"."+strconv.Itoa(iter))
				if err != nil {
					return nil, err
				}
				for nestedKey, nestedValue := range nestedDiff {
					mergedNestedDiffs[nestedKey] = nestedValue
				}
				iter++
				continue
			}
			// If we no longer have room to compare, append the remainder of whoever has remainder
			if iter < leftLen {
				for j, leftVal := range leftArray[iter:] {
					mergedNestedDiffs[path+"."+strconv.Itoa(iter+j)] = Diff{
						From: gjsonResultToInterface(leftVal),
						To:   nil,
					}
				}
			}
			if iter < rightLen {
				for j, rightVal := range rightArray[iter:] {
					mergedNestedDiffs[path+"."+strconv.Itoa(iter+j)] = Diff{
						From: nil,
						To:   gjsonResultToInterface(rightVal),
					}
				}
			}
			break
		}
		if len(mergedNestedDiffs) == 0 {
			return nil, nil
		}
		return mergedNestedDiffs, nil
	}

	// Handle scalar values
	leftVal := gjsonResultToInterface(left)
	rightVal := gjsonResultToInterface(right)
	if leftVal != rightVal {
		return map[string]Diff{
			path: {
				From: leftVal,
				To:   rightVal,
			},
		}, nil
	}
	return nil, nil
}

// gjsonResultToInterface is a helper function to get the underlying value out of a gjson result.
//
// gjson will let you ask for the string, int, or whatever representation of any value, regardless
// of if a valid one exists. This helper function just switches based on the type to return the
// correct value.
func gjsonResultToInterface(result gjson.Result) interface{} {
	switch result.Type {
	default:
		return result.Raw
	case gjson.Null:
		return nil
	case gjson.False:
		return false
	case gjson.Number:
		// We can't differentiate between ints & floats based on the gjson type, so we try to parse
		// as one then the other
		intValue, err := strconv.Atoi(result.Raw)
		if err == nil {
			return intValue
		}
		return result.Num
	case gjson.String:
		return result.String()
	case gjson.True:
		return true
	case gjson.JSON:
		// TODO not ideal to return the raw json, could/should recurse and return map/array as appropriate
		return result.Raw
	}
}
