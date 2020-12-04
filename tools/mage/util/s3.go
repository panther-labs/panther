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

	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"go.uber.org/zap"
)

// The name of the bucket containing published Panther releases
func PublicAssetsBucket(region string) string {
	return "panther-community-" + region
}

// Upload a local file to S3.
func UploadFileToS3(log *zap.SugaredLogger, uploader *s3manager.Uploader, path, bucket, key string) (*s3manager.UploadOutput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	log.Debugf("uploading %s to s3://%s/%s", path, bucket, key)
	return uploader.Upload(&s3manager.UploadInput{
		Body:   file,
		Bucket: &bucket,
		Key:    &key,
	})
}
