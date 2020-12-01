package s3list

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
	"log"
	"math"
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pkg/errors"
)

const (
	pageSize       = 1000
	progressNotify = 5000 // log a line every this many to show progress
)

type Stats struct {
	NumFiles uint64
	NumBytes uint64
}

// ListPath given an s3path (e.g., s3://mybucket/myprefix) list files and send to notifyChan, sending errors on errChan
func ListPath(s3Client s3iface.S3API, s3path string, limit uint64,
	notifyChan chan *events.S3Event, errChan chan error, stats *Stats) {

	if limit == 0 {
		limit = math.MaxUint64
	}

	defer func() {
		close(notifyChan) // signal to reader that we are done
	}()

	parsedPath, err := url.Parse(s3path)
	if err != nil {
		errChan <- errors.Errorf("bad s3 url: %s,", err)
		return
	}

	if parsedPath.Scheme != "s3" {
		errChan <- errors.Errorf("not s3 protocol (expecting s3://): %s,", s3path)
		return
	}

	bucket := parsedPath.Host
	if bucket == "" {
		errChan <- errors.Errorf("missing bucket: %s,", s3path)
		return
	}
	var prefix string
	if len(parsedPath.Path) > 0 {
		prefix = parsedPath.Path[1:] // remove leading '/'
	}

	// list files w/pagination
	inputParams := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int64(pageSize),
	}
	err = s3Client.ListObjectsV2Pages(inputParams, func(page *s3.ListObjectsV2Output, morePages bool) bool {
		for _, value := range page.Contents {
			if *value.Size > 0 { // we only care about objects with size
				stats.NumFiles++
				if stats.NumFiles%progressNotify == 0 {
					log.Printf("listed %d files ...", stats.NumFiles)
				}
				stats.NumBytes += (uint64)(*value.Size)
				notifyChan <- &events.S3Event{
					Records: []events.S3EventRecord{
						{
							S3: events.S3Entity{
								Bucket: events.S3Bucket{
									Name: bucket,
								},
								Object: events.S3Object{
									Key:  *value.Key,
									Size: *value.Size,
								},
							},
						},
					},
				}
				if stats.NumFiles >= limit {
					break
				}
			}
		}
		return stats.NumFiles < limit // "To stop iterating, return false from the fn function."
	})
	if err != nil {
		errChan <- err
	}
}
