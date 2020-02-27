package awsglue

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
