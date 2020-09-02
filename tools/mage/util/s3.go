package util

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
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"

	"github.com/panther-labs/panther/tools/mage/clients"
)

// The name of the bucket containing published Panther releases
func PublicAssetsBucket() string {
	return "panther-community-" + clients.Region()
}

// Upload a local file to S3.
func UploadFileToS3(path, bucket, key string) (*s3manager.UploadOutput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	log.Debugf("uploading %s to s3://%s/%s", path, bucket, key)
	return clients.S3Uploader().Upload(&s3manager.UploadInput{
		Body:   file,
		Bucket: &bucket,
		Key:    &key,
	})
}

// Find the most recent published version of Panther in S3, e.g. "1.7.1"
//
// This provides an alternative to checking the git tags in the repo.
func LatestPublishedVersion() (string, error) {
	bucket := PublicAssetsBucket()
	input := &s3.ListObjectsV2Input{
		Bucket: &bucket,
		// Packaged assets are hex and will not start with 'v'.
		// This will match only published master templates, e.g. "v1.7.1/master.yml"
		Prefix: aws.String("v"),
	}

	// Sorting versions by string is not sufficient ("v1.10.0" < "v1.3.0")
	// Instead, keep track of the semver components
	type semver struct {
		major int
		minor int
		patch int
	}
	var versions []semver

	err := clients.S3().ListObjectsV2Pages(input, func(page *s3.ListObjectsV2Output, _ bool) bool {
		for _, object := range page.Contents {
			if strings.HasSuffix(*object.Key, "panther.yml") {
				// "v1.7.1/panther.yml" => "1.7.1"
				version := strings.TrimPrefix(*object.Key, "v")
				version = strings.TrimSuffix(version, "/panther.yml")
				split := strings.Split(version, ".")

				versions = append(versions, semver{
					major: mustParseInt(split[0]),
					minor: mustParseInt(split[1]),
					patch: mustParseInt(split[2]),
				})
			}
		}
		return true
	})
	if err != nil {
		return "", err
	}

	sort.Slice(versions, func(i, j int) bool {
		if versions[i].major != versions[j].major {
			return versions[i].major < versions[j].major
		}
		if versions[i].minor != versions[j].minor {
			return versions[i].minor < versions[j].minor
		}
		return versions[i].patch < versions[j].patch
	})

	log.Debugf("found %d published versions in %s: %v", len(versions), bucket, versions)
	latest := versions[len(versions)-1]
	return fmt.Sprintf("%d.%d.%d", latest.major, latest.minor, latest.patch), nil
}

func mustParseInt(x string) int {
	result, err := strconv.Atoi(x)
	if err != nil {
		log.Fatalf("expected int: %s: %v", x, err)
	}
	return result
}
