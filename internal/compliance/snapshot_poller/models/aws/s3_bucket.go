package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import "github.com/aws/aws-sdk-go/service/s3"

// S3BucketSchema is the name of the S3Bucket Schema
const S3BucketSchema = "AWS.S3.Bucket"

// S3Bucket contains all information about an S3 bucket.
type S3Bucket struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Additional fields
	EncryptionRules                []*s3.ServerSideEncryptionRule
	Grants                         []*s3.Grant
	LifecycleRules                 []*s3.LifecycleRule
	LoggingPolicy                  *s3.LoggingEnabled
	MFADelete                      *string
	ObjectLockConfiguration        *s3.ObjectLockConfiguration
	Owner                          *s3.Owner
	Policy                         *string
	PublicAccessBlockConfiguration *s3.PublicAccessBlockConfiguration
	Versioning                     *string
}
