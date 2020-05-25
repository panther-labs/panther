package cloudwatchcf

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
	"fmt"
)

func getResourceProperty(key string, resource map[string]interface{}) string {
	switch props := resource["Properties"].(type) {
	case map[string]interface{}:
		switch val := props[key].(type) {
		case string:
			return val
		case float32, float64:
			return fmt.Sprintf("%f", val)
		case int, int32, int64:
			return fmt.Sprintf("%d", val)
		}
	}
	panic(fmt.Sprintf("Cannot find name: %s in %#v", key, resource["Properties"]))
}
