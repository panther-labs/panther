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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// CloudTrailDigestDesc describes a cloud trail digest log
// nolint:lll
var CloudTrailDigestDesc = `AWSCloudTrailDigest contains the names of the log files that were delivered to your Amazon S3 bucket during the last hour, the hash values for those log files, and the signature of the previous digest file. 
Log format & samples can be seen here: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html`

// nolint:lll
type CloudTrailDigest struct {
	AWSAccountID                *string                   `json:"awsAccountId" validate:"required" description:"The AWS account ID for which the digest file has been delivered."`
	DigestStartTime             *timestamp.RFC3339        `json:"digestStartTime" validate:"required" description:"The starting UTC time range that the digest file covers, taking as a reference the time in which log files have been delivered by CloudTrail."`
	DigestEndTime               *timestamp.RFC3339        `json:"digestEndTime" validate:"required" description:"The ending UTC time range that the digest file covers, taking as a reference the time in which log files have been delivered by CloudTrail."`
	DigestS3Bucket              *string                   `json:"digestS3Bucket" validate:"required" description:"The name of the Amazon S3 bucket to which the current digest file has been delivered."`
	DigestS3Object              *string                   `json:"digestS3Object" validate:"required" description:"The Amazon S3 object key (that is, the Amazon S3 bucket location) of the current digest file."`
	NewestEventTime             *timestamp.RFC3339        `json:"newestEventTime,omitempty" description:"The UTC time of the most recent event among all of the events in the log files in the digest."`
	OldestEventTime             *timestamp.RFC3339        `json:"oldestEventTime,omitempty" description:"The UTC time of the oldest event among all of the events in the log files in the digest. "`
	PreviousDigestS3Bucket      *string                   `json:"previousDigestS3Bucket,omitempty" description:"The Amazon S3 bucket to which the previous digest file was delivered."`
	PreviousDigestS3Object      *string                   `json:"previousDigestS3Object,omitempty" description:"The Amazon S3 object key (that is, the Amazon S3 bucket location) of the previous digest file."`
	PreviousDigestHashValue     *string                   `json:"previousDigestHashValue,omitempty" description:"The hexadecimal encoded hash value of the uncompressed contents of the previous digest file."`
	PreviousDigestHashAlgorithm *string                   `json:"previousDigestHashAlgorithm,omitempty" description:"The name of the hash algorithm that was used to hash the previous digest file."`
	PreviousDigestSignature     *string                   `json:"previousDigestSignature,omitempty" description:"The hexadecimal encoded signature of the previous digest file."`
	DigestPublicKeyFingerprint  *string                   `json:"digestPublicKeyFingerprint" validate:"required" description:"The hexadecimal encoded fingerprint of the public key that matches the private key used to sign this digest file."`
	DigestSignatureAlgorithm    *string                   `json:"digestSignatureAlgorithm" validate:"required" description:"The algorithm used to sign the digest file."`
	LogFiles                    []CloudTrailDigestLogFile `json:"logFiles" validate:"required,min=0" description:"Log files delivered in this digest"`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// nolint:lll
type CloudTrailDigestLogFile struct {
	S3Bucket        *string            `json:"s3Bucket" validate:"required" description:"The name of the Amazon S3 bucket for the log file."`
	S3Object        *string            `json:"s3Object" validate:"required" description:"The Amazon S3 object key of the current log file."`
	HashValue       *string            `json:"hashValue" validate:"required" description:"The hexadecimal encoded hash value of the uncompressed log file content."`
	HashAlgorithm   *string            `json:"hashAlgorithm" validate:"required" description:"The hash algorithm used to hash the log file."`
	NewestEventTime *timestamp.RFC3339 `json:"newestEventTime" validate:"required" description:"The UTC time of the most recent event among the events in the log file."`
	OldestEventTime *timestamp.RFC3339 `json:"oldestEventTime" validate:"required" description:"The UTC time of the oldest event among the events in the log file."`
}

type CloudTrailDigestParser struct{}

// NOTE: guard to ensure interface implementation
var _ parsers.LogParser = (*CloudTrailDigestParser)(nil)

func (p *CloudTrailDigestParser) New() parsers.LogParser {
	return &CloudTrailDigestParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *CloudTrailDigestParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := &CloudTrailDigest{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		return nil, err
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}
	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *CloudTrailDigestParser) LogType() string {
	return "AWS.CloudTrailDigest"
}

func (event *CloudTrailDigest) updatePantherFields(p *CloudTrailDigestParser) {
	// Use end time as it's the time the digest was actually delivered
	event.SetCoreFields(p.LogType(), event.DigestEndTime, event)
	event.AppendAnyAWSAccountIdPtrs(event.AWSAccountID)
	event.AppendAnySHA256HashesPtr(event.PreviousDigestHashValue)
	for _, logFile := range event.LogFiles {
		event.AppendAnySHA256HashesPtr(logFile.HashValue)
	}
}
