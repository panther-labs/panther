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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGlueTableTimebinNext(t *testing.T) {
	var tb GlueTableTimebin
	refTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// hour and day are fixed offsets, so only need simple tests

	// test hour ...
	tb = GlueTableHourly
	expectedTime := refTime.Add(time.Hour)
	next := tb.Next(refTime)
	assert.Equal(t, expectedTime, next)

	// test day ...
	tb = GlueTableDaily
	expectedTime = refTime.Add(time.Hour * 24)
	next = tb.Next(refTime)
	assert.Equal(t, expectedTime, next)

	// test month ... this needs to test crossing year boundaries
	tb = GlueTableMonthly
	// Jan to Feb
	refTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	expectedTime = time.Date(2020, 2, 1, 0, 0, 0, 0, time.UTC)
	next = tb.Next(refTime)
	assert.Equal(t, expectedTime, next)
	// Dec to Jan, over year boundary
	refTime = time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC)
	expectedTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	next = tb.Next(refTime)
	assert.Equal(t, expectedTime, next)
}
