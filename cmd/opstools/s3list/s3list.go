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
	"context"
	"math"
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	pageSize       = 1000
	progressNotify = 5000 // log a line every this many to show progress
)

type Input struct {
	Logger   *zap.SugaredLogger
	S3Client s3iface.S3API
	S3Path   string
	Limit    uint64
	Loop     bool
	Write    func(*events.S3Event) // called on each event
	Done     func()                // called when complete
	Stats    *Stats
}

type Stats struct {
	NumFiles uint64
	NumBytes uint64
}

// ListPath given an s3path (e.g., s3://mybucket/myprefix) list files and send to notifyChan
func ListPath(ctx context.Context, input *Input) (err error) {
	defer input.Done()

	limit := input.Limit
	if limit == 0 {
		limit = math.MaxUint64
	}

	parsedPath, err := url.Parse(input.S3Path)
	if err != nil {
		return errors.Wrapf(err, "bad s3 url: %s,", input.S3Path)
	}

	if parsedPath.Scheme != "s3" {
		return errors.Errorf("not s3 protocol (expecting s3://): %s,", input.S3Path)
	}

	bucket := parsedPath.Host
	if bucket == "" {
		return errors.Errorf("missing bucket: %s,", input.S3Path)
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

	stop := false // stop will be set to true if signaled by context or limit is reached

	listObjects := func() error {
		return input.S3Client.ListObjectsV2Pages(inputParams, func(page *s3.ListObjectsV2Output, morePages bool) bool {
			select {
			case <-ctx.Done(): // signal from workers that they were canceled
				stop = true
				return false
			default: // non blocking
			}

			for _, value := range page.Contents {
				if *value.Size > 0 { // we only care about objects with size
					input.Stats.NumFiles++
					if input.Stats.NumFiles%progressNotify == 0 {
						input.Logger.Infof("listed %d files ...", input.Stats.NumFiles)
					}
					input.Stats.NumBytes += (uint64)(*value.Size)
					input.Write(&events.S3Event{
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
					})
					if input.Stats.NumFiles >= limit {
						stop = true
						break
					}
				}
			}
			return input.Stats.NumFiles < limit // "To stop iterating, return false from the fn function."
		})
	}

	// infinite loop (unless canceled, limit exceeded or error)
	if input.Loop {
		for !stop {
			err = listObjects()
			if err != nil {
				return err
			}
		}
	}

	return listObjects()
}

func GetS3Region(sess *session.Session, s3Path string) (string, error) {
	parsedPath, err := url.Parse(s3Path)
	if err != nil {
		return "", errors.Wrapf(err, "failed to find bucket region for provided path %s: %s", s3Path, err)
	}

	input := &s3.GetBucketLocationInput{Bucket: aws.String(parsedPath.Host)}
	location, err := s3.New(sess).GetBucketLocation(input)
	if err != nil {
		return "", errors.Wrapf(err, "failed to find bucket region for provided path %s: %s", s3Path, err)
	}

	// Method may return nil if region is us-east-1,https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
	// and https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
	if location.LocationConstraint == nil {
		return endpoints.UsEast1RegionID, nil
	}
	return *location.LocationConstraint, nil
}
