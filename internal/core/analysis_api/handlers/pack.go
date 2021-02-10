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
	"time"

	"go.uber.org/zap"
)

// Create/update a pack
//
// The following fields are set automatically (need not be set by the caller):
//     CreatedAt, CreatedBy, LastModified, LastModifiedBy, VersionID
//
// To update an existing item,              mustExist = aws.Bool(true)
// To create a new item (with a unique ID), mustExist = aws.Bool(false)
// To allow either an update or a create,   mustExist = nil (neither)
//
// The first return value indicates what kind of change took place (none, new item, updated item).
func writePack(item *packTableItem, userID string, mustExist *bool) error {
	oldItem, err := dynamoGetPack(item.ID, true)
	if err != nil {
		return err
	}

	if mustExist != nil {
		if *mustExist && oldItem == nil {
			return errNotExists // item should exist but does not (update)
		}
		if !*mustExist && oldItem != nil {
			return errExists // item exists but should not (create)
		}
	}

	if oldItem == nil {
		item.CreatedAt = time.Now()
		item.CreatedBy = userID
	} else {
		if equal := !packUpdated(oldItem, item); equal {
			zap.L().Info("no changes necessary", zap.String("packId", item.ID))
			return nil
		}
		// If there was an error evaluating equality, just assume they are not equal and continue
		// with the update as normal.

		item.CreatedAt = oldItem.CreatedAt
		item.CreatedBy = oldItem.CreatedBy
	}

	item.LastModified = time.Now()
	item.LastModifiedBy = userID

	// Write to Dynamo
	if err := dynamoPutPack(item); err != nil {
		return err
	}

	return nil
}

// packUpdated checks if ANY field has been changed between the old and new pack item
//
// DO NOT use this for situations the items MUST be exactly equal, this is a "good enough" approximation for the
// purpose it serves, which is informing users that their bulk operation did or did not change something.
func packUpdated(oldItem, newItem *packTableItem) bool {
	itemsEqual := oldItem.Description == newItem.Description &&
		oldItem.DisplayName == newItem.DisplayName &&
		oldItem.Enabled == newItem.Enabled &&
		oldItem.PackVersion.ID == newItem.PackVersion.ID &&
		oldItem.UpdateAvailable == newItem.UpdateAvailable &&
		len(oldItem.AvailableVersions) == len(newItem.AvailableVersions)
	if !itemsEqual {
		return true
	}
	// check detection patterns, which currently only cover IDs
	itemsEqual = itemsEqual && !setEquality(oldItem.PackDefinition.IDs, newItem.PackDefinition.IDs)
	return !itemsEqual
}
