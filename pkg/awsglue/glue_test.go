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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

const (
	s3Prefix = "foo/"
)

func TestGlueMetadata_PartitionPrefix(t *testing.T) {
	var gm *GlueMetadata
	var expected string

	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)

	gm = &GlueMetadata{
		s3Prefix:     s3Prefix,
		timebin:      GlueTableHourly,
		timeUnpadded: false,
	}
	expected = "foo/year=2020/month=01/day=03/hour=01/"
	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
	gm.timeUnpadded = true
	expected = "foo/year=2020/month=1/day=3/hour=1/"
	assert.Equal(t, expected, gm.PartitionPrefix(refTime))

	gm = &GlueMetadata{
		s3Prefix:     s3Prefix,
		timebin:      GlueTableDaily,
		timeUnpadded: false,
	}
	expected = "foo/year=2020/month=01/day=03/"
	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
	gm.timeUnpadded = true
	expected = "foo/year=2020/month=1/day=3/"
	assert.Equal(t, expected, gm.PartitionPrefix(refTime))

	gm = &GlueMetadata{
		s3Prefix:     s3Prefix,
		timebin:      GlueTableMonthly,
		timeUnpadded: false,
	}
	expected = "foo/year=2020/month=01/"
	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
	gm.timeUnpadded = true
	expected = "foo/year=2020/month=1/"
	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
}

func TestGlueMetadata_PartitionValues(t *testing.T) {
	var gm *GlueMetadata
	var expected []*string

	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)

	gm = &GlueMetadata{
		s3Prefix:     s3Prefix,
		timebin:      GlueTableHourly,
		timeUnpadded: false,
	}
	expected = []*string{
		aws.String(fmt.Sprintf("%d", refTime.Year())),
		aws.String(fmt.Sprintf("%02d", refTime.Month())),
		aws.String(fmt.Sprintf("%02d", refTime.Day())),
		aws.String(fmt.Sprintf("%02d", refTime.Hour())),
	}
	assert.Equal(t, expected, gm.PartitionValues(refTime))
	gm.timeUnpadded = true
	expected = []*string{
		aws.String(fmt.Sprintf("%d", refTime.Year())),
		aws.String(fmt.Sprintf("%d", refTime.Month())),
		aws.String(fmt.Sprintf("%d", refTime.Day())),
		aws.String(fmt.Sprintf("%d", refTime.Hour())),
	}
	assert.Equal(t, expected, gm.PartitionValues(refTime))

	gm = &GlueMetadata{
		s3Prefix:     s3Prefix,
		timebin:      GlueTableDaily,
		timeUnpadded: false,
	}
	expected = []*string{
		aws.String(fmt.Sprintf("%d", refTime.Year())),
		aws.String(fmt.Sprintf("%02d", refTime.Month())),
		aws.String(fmt.Sprintf("%02d", refTime.Day())),
	}
	assert.Equal(t, expected, gm.PartitionValues(refTime))
	gm.timeUnpadded = true
	expected = []*string{
		aws.String(fmt.Sprintf("%d", refTime.Year())),
		aws.String(fmt.Sprintf("%d", refTime.Month())),
		aws.String(fmt.Sprintf("%d", refTime.Day())),
	}
	assert.Equal(t, expected, gm.PartitionValues(refTime))

	gm = &GlueMetadata{
		s3Prefix:     s3Prefix,
		timebin:      GlueTableMonthly,
		timeUnpadded: false,
	}
	expected = []*string{
		aws.String(fmt.Sprintf("%d", refTime.Year())),
		aws.String(fmt.Sprintf("%02d", refTime.Month())),
	}
	assert.Equal(t, expected, gm.PartitionValues(refTime))
	gm.timeUnpadded = true
	expected = []*string{
		aws.String(fmt.Sprintf("%d", refTime.Year())),
		aws.String(fmt.Sprintf("%d", refTime.Month())),
	}
	assert.Equal(t, expected, gm.PartitionValues(refTime))
}
