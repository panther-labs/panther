package cloudwatchcf

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
	"fmt"
	"strconv"
)

func getResourceFloat32Property(key string, resource map[interface{}]interface{}) float32 {
	floatVal, err := strconv.ParseFloat(getResourceProperty(key, resource), 32)
	if err != nil {
		panic(fmt.Sprintf("cannot parse %s as float32: from %#v",
			getResourceProperty(key, resource), resource))
	}
	return (float32)(floatVal)
}

func getResourceProperty(key string, resource map[interface{}]interface{}) string {
	switch props := resource[(interface{})("Properties")].(type) {
	case map[interface{}]interface{}:
		switch val := props[(interface{})(key)].(type) {
		case string:
			return val
		case int, int32, int64:
			return fmt.Sprintf("%d", val)
		}
	}
	panic(fmt.Sprintf("Cannot find name: %s in %#v", key, resource))
}
