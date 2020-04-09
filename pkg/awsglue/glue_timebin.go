package awsglue

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
	"time"
)

// Use this to tag the time partitioning used in a GlueTableMetadata table
type GlueTableTimebin int

const (
	GlueTableMonthly GlueTableTimebin = iota + 1
	GlueTableDaily
	GlueTableHourly
)

func (tb GlueTableTimebin) Validate() (err error) {
	switch tb {
	case GlueTableHourly, GlueTableDaily, GlueTableMonthly:
		return
	default:
		err = fmt.Errorf("unknown GlueTableMetadata table time bin: %d", tb)
	}
	return
}

// return the next time interval
func (tb GlueTableTimebin) Next(t time.Time) (next time.Time) {
	switch tb {
	case GlueTableHourly:
		return t.Add(time.Hour).Truncate(time.Hour)
	case GlueTableDaily:
		return t.Add(time.Hour * 24).Truncate(time.Hour * 24)
	case GlueTableMonthly:
		// loop a day at a time until the month changes
		currentMonth := t.Month()
		for next = t.Add(time.Hour * 24).Truncate(time.Hour * 24); next.Month() == currentMonth; next = next.Add(time.Hour * 24) {
		}
		return next
	default:
		panic(fmt.Sprintf("unknown GlueTableMetadata table time bin: %d", tb))
	}
}
