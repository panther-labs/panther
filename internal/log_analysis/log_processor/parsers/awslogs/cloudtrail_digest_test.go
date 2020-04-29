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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestCloudTrailDigestParser(t *testing.T) {
	//nolint:lll
	log := `{
		"awsAccountId": "111122223333",
		"digestStartTime": "2015-08-17T14:01:31Z",
		"digestEndTime": "2015-08-17T15:01:31Z",
		"digestS3Bucket": "S3-bucket-name",
		"digestS3Object": "AWSLogs/111122223333/CloudTrail-Digest/us-east-2/2015/08/17/111122223333_CloudTrail-Digest_us-east-2_your-trail-name_us-east-2_20150817T150131Z.json.gz",
		"digestPublicKeyFingerprint": "31e8b5433410dfb61a9dc45cc65b22ff",
		"digestSignatureAlgorithm": "SHA256withRSA",
		"newestEventTime": "2015-08-17T14:52:27Z",
		"oldestEventTime": "2015-08-17T14:42:27Z",
		"previousDigestS3Bucket": "S3-bucket-name",
		"previousDigestS3Object": "AWSLogs/111122223333/CloudTrail-Digest/us-east-2/2015/08/17/111122223333_CloudTrail-Digest_us-east-2_your-trail-name_us-east-2_20150817T140131Z.json.gz",
		"previousDigestHashValue": "97fb791cf91ffc440d274f8190dbdd9aa09c34432aba82739df18b6d3c13df2d",
		"previousDigestHashAlgorithm": "SHA-256",
		"previousDigestSignature": "50887ccffad4c002b97caa37cc9dc626e3c680207d41d27fa5835458e066e0d3652fc4dfc30937e4d5f4cc7f796e7a258fb50a43ac427f2237f6e505d4efaf373d156e15e3b68dea9f58111d395b62628d6bd367a9024d2183b5c5f6e19466d3a996b92df705bc997b8a0e13430f241d733cf95df4e41bb6c304c3f58363043572ea57a27085639ce187e679c0d81c7519b1184fa77fb7ab0b0e40a32dace6e1eefc3995c5ae182da49b62b26398cebb52a2201a6387b75b89c83e5570bcb9bba6c34a80f2f00a1c6ebe07d1ff149eccd812dc805bb3eeff6657db32a6cb48d2d096404eb76181877bc6ebb8cd0b23f823200155b2fd8848d428e46e8456328a",
		"logFiles": [
			{
				"s3Bucket": "S3-bucket-name",
				"s3Object": "AWSLogs/111122223333/CloudTrail/us-east-2/2015/08/17/111122223333_CloudTrail_us-east-2_20150817T1445Z_9nYN7gp2eWAJHIfT.json.gz",
				"hashValue": "9bb6196fc6b84d6f075a56548feca262bd99ba3c2de41b618e5b6e22c1fc71f6",
				"hashAlgorithm": "SHA-256",
				"newestEventTime": "2015-08-17T14:52:27Z",
				"oldestEventTime": "2015-08-17T14:42:27Z"
			}
		]
	}`

	expectedDateStart := time.Date(2015, 8, 17, 14, 1, 31, 0, time.UTC)
	expectedDateMin := time.Date(2015, 8, 17, 14, 42, 27, 0, time.UTC)
	expectedDateMax := time.Date(2015, 8, 17, 14, 52, 27, 0, time.UTC)
	expectedDateEnd := time.Date(2015, 8, 17, 15, 1, 31, 0, time.UTC)
	// nolint:lll
	expectedEvent := &CloudTrailDigest{
		AWSAccountID:                aws.String("111122223333"),
		DigestStartTime:             (*timestamp.RFC3339)(&expectedDateStart),
		DigestEndTime:               (*timestamp.RFC3339)(&expectedDateEnd),
		DigestS3Bucket:              aws.String("S3-bucket-name"),
		DigestS3Object:              aws.String("AWSLogs/111122223333/CloudTrail-Digest/us-east-2/2015/08/17/111122223333_CloudTrail-Digest_us-east-2_your-trail-name_us-east-2_20150817T150131Z.json.gz"),
		DigestPublicKeyFingerprint:  aws.String("31e8b5433410dfb61a9dc45cc65b22ff"),
		DigestSignatureAlgorithm:    aws.String("SHA256withRSA"),
		NewestEventTime:             (*timestamp.RFC3339)(&expectedDateMax),
		OldestEventTime:             (*timestamp.RFC3339)(&expectedDateMin),
		PreviousDigestS3Bucket:      aws.String("S3-bucket-name"),
		PreviousDigestS3Object:      aws.String("AWSLogs/111122223333/CloudTrail-Digest/us-east-2/2015/08/17/111122223333_CloudTrail-Digest_us-east-2_your-trail-name_us-east-2_20150817T140131Z.json.gz"),
		PreviousDigestHashValue:     aws.String("97fb791cf91ffc440d274f8190dbdd9aa09c34432aba82739df18b6d3c13df2d"),
		PreviousDigestHashAlgorithm: aws.String("SHA-256"),
		PreviousDigestSignature:     aws.String("50887ccffad4c002b97caa37cc9dc626e3c680207d41d27fa5835458e066e0d3652fc4dfc30937e4d5f4cc7f796e7a258fb50a43ac427f2237f6e505d4efaf373d156e15e3b68dea9f58111d395b62628d6bd367a9024d2183b5c5f6e19466d3a996b92df705bc997b8a0e13430f241d733cf95df4e41bb6c304c3f58363043572ea57a27085639ce187e679c0d81c7519b1184fa77fb7ab0b0e40a32dace6e1eefc3995c5ae182da49b62b26398cebb52a2201a6387b75b89c83e5570bcb9bba6c34a80f2f00a1c6ebe07d1ff149eccd812dc805bb3eeff6657db32a6cb48d2d096404eb76181877bc6ebb8cd0b23f823200155b2fd8848d428e46e8456328a"),
		LogFiles: []CloudTrailDigestLogFile{
			{
				S3Bucket:        aws.String("S3-bucket-name"),
				S3Object:        aws.String("AWSLogs/111122223333/CloudTrail/us-east-2/2015/08/17/111122223333_CloudTrail_us-east-2_20150817T1445Z_9nYN7gp2eWAJHIfT.json.gz"),
				HashValue:       aws.String("9bb6196fc6b84d6f075a56548feca262bd99ba3c2de41b618e5b6e22c1fc71f6"),
				HashAlgorithm:   aws.String("SHA-256"),
				NewestEventTime: (*timestamp.RFC3339)(&expectedDateMax),
				OldestEventTime: (*timestamp.RFC3339)(&expectedDateMin),
			},
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.CloudTrailDigest")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDateEnd)
	expectedEvent.AppendAnyAWSAccountIds("111122223333")
	expectedEvent.AppendAnySHA256Hashes(
		"97fb791cf91ffc440d274f8190dbdd9aa09c34432aba82739df18b6d3c13df2d",
		"9bb6196fc6b84d6f075a56548feca262bd99ba3c2de41b618e5b6e22c1fc71f6",
	)
	expectedEvent.SetEvent(expectedEvent)
	testutil.CheckPantherParser(t, log, &CloudTrailDigestParser{}, expectedEvent.Log())
}
func TestCloudTrailDigestParserFirstRecord(t *testing.T) {
	//nolint:lll
	log := `{
		"awsAccountId": "123456789012",
		"digestStartTime": "2020-04-21T12:28:23Z",
		"digestEndTime": "2020-04-21T13:28:23Z",
		"digestS3Bucket": "cloudtrail-test-eu-west-1",
		"digestS3Object": "AWSLogs/123456789012/CloudTrail-Digest/eu-west-1/2020/04/21/123456789012_CloudTrail-Digest_eu-west-1_TestTrail_eu-west-1_20200421T132823Z.json.gz",
		"digestPublicKeyFingerprint": "f0249abde0f55218ac45bd3750055109",
		"digestSignatureAlgorithm": "SHA256withRSA",
		"newestEventTime": null,
		"oldestEventTime": null,
		"previousDigestS3Bucket": null,
		"previousDigestS3Object": null,
		"previousDigestHashValue": null,
		"previousDigestHashAlgorithm": null,
		"previousDigestSignature": null,
		"logFiles": []
	}`

	expectedDateStart := time.Date(2020, 4, 21, 12, 28, 23, 0, time.UTC)
	expectedDateEnd := time.Date(2020, 4, 21, 13, 28, 23, 0, time.UTC)
	// nolint:lll
	expectedEvent := &CloudTrailDigest{
		AWSAccountID:                aws.String("123456789012"),
		DigestStartTime:             (*timestamp.RFC3339)(&expectedDateStart),
		DigestEndTime:               (*timestamp.RFC3339)(&expectedDateEnd),
		DigestS3Bucket:              aws.String("cloudtrail-test-eu-west-1"),
		DigestS3Object:              aws.String("AWSLogs/123456789012/CloudTrail-Digest/eu-west-1/2020/04/21/123456789012_CloudTrail-Digest_eu-west-1_TestTrail_eu-west-1_20200421T132823Z.json.gz"),
		DigestPublicKeyFingerprint:  aws.String("f0249abde0f55218ac45bd3750055109"),
		DigestSignatureAlgorithm:    aws.String("SHA256withRSA"),
		NewestEventTime:             (*timestamp.RFC3339)(nil),
		OldestEventTime:             (*timestamp.RFC3339)(nil),
		PreviousDigestS3Bucket:      nil,
		PreviousDigestS3Object:      nil,
		PreviousDigestHashValue:     nil,
		PreviousDigestHashAlgorithm: nil,
		PreviousDigestSignature:     nil,
		LogFiles:                    []CloudTrailDigestLogFile{},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.CloudTrailDigest")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDateEnd)
	expectedEvent.AppendAnyAWSAccountIds("123456789012")
	expectedEvent.SetEvent(expectedEvent)
	testutil.CheckPantherParser(t, log, &CloudTrailDigestParser{}, expectedEvent.Log())
}

func TestCloudTrailDigestLogType(t *testing.T) {
	parser := &CloudTrailDigestParser{}
	require.Equal(t, "AWS.CloudTrailDigest", parser.LogType())
}
