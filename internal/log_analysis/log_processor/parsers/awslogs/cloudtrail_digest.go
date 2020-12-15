package awslogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// nolint:lll
type CloudTrailDigest struct {
	AWSAccountID                pantherlog.String         `json:"awsAccountId" panther:"aws_account_id" validate:"required" description:"The AWS account ID for which the digest file has been delivered."`
	DigestStartTime             pantherlog.Time           `json:"digestStartTime" tcodec:"rfc3339" validate:"required" description:"The starting UTC time range that the digest file covers, taking as a reference the time in which log files have been delivered by CloudTrail."`
	DigestEndTime               pantherlog.Time           `json:"digestEndTime" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The ending UTC time range that the digest file covers, taking as a reference the time in which log files have been delivered by CloudTrail."`
	DigestS3Bucket              pantherlog.String         `json:"digestS3Bucket" validate:"required" description:"The name of the Amazon S3 bucket to which the current digest file has been delivered."`
	DigestS3Object              pantherlog.String         `json:"digestS3Object" validate:"required" description:"The Amazon S3 object key (that is, the Amazon S3 bucket location) of the current digest file."`
	NewestEventTime             pantherlog.Time           `json:"newestEventTime" tcodec:"rfc3339" description:"The UTC time of the most recent event among all of the events in the log files in the digest."`
	OldestEventTime             pantherlog.Time           `json:"oldestEventTime" tcodec:"rfc3339" description:"The UTC time of the oldest event among all of the events in the log files in the digest. "`
	PreviousDigestS3Bucket      pantherlog.String         `json:"previousDigestS3Bucket" description:"The Amazon S3 bucket to which the previous digest file was delivered."`
	PreviousDigestS3Object      pantherlog.String         `json:"previousDigestS3Object" description:"The Amazon S3 object key (that is, the Amazon S3 bucket location) of the previous digest file."`
	PreviousDigestHashValue     pantherlog.String         `json:"previousDigestHashValue" panther:"sha256" description:"The hexadecimal encoded hash value of the uncompressed contents of the previous digest file."`
	PreviousDigestHashAlgorithm pantherlog.String         `json:"previousDigestHashAlgorithm" description:"The name of the hash algorithm that was used to hash the previous digest file."`
	PreviousDigestSignature     pantherlog.String         `json:"previousDigestSignature" description:"The hexadecimal encoded signature of the previous digest file."`
	DigestPublicKeyFingerprint  pantherlog.String         `json:"digestPublicKeyFingerprint" validate:"required" description:"The hexadecimal encoded fingerprint of the public key that matches the private key used to sign this digest file."`
	DigestSignatureAlgorithm    pantherlog.String         `json:"digestSignatureAlgorithm" validate:"required" description:"The algorithm used to sign the digest file."`
	LogFiles                    []CloudTrailDigestLogFile `json:"logFiles" validate:"required,min=0" description:"Log files delivered in this digest"`
}

// nolint:lll
type CloudTrailDigestLogFile struct {
	S3Bucket        pantherlog.String `json:"s3Bucket" validate:"required" description:"The name of the Amazon S3 bucket for the log file."`
	S3Object        pantherlog.String `json:"s3Object" validate:"required" description:"The Amazon S3 object key of the current log file."`
	HashValue       pantherlog.String `json:"hashValue" panther:"sha256" validate:"required" description:"The hexadecimal encoded hash value of the uncompressed log file content."`
	HashAlgorithm   pantherlog.String `json:"hashAlgorithm" validate:"required" description:"The hash algorithm used to hash the log file."`
	NewestEventTime pantherlog.Time   `json:"newestEventTime" tcodec:"rfc3339" validate:"required" description:"The UTC time of the most recent event among the events in the log file."`
	OldestEventTime pantherlog.Time   `json:"oldestEventTime" tcodec:"rfc3339" validate:"required" description:"The UTC time of the oldest event among the events in the log file."`
}
