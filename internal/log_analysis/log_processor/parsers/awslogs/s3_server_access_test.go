package awslogs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

func TestS3AccessLogGetHttpOk(t *testing.T) {
	//nolint:lll
	log := "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket [06/Feb/2019:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be 3E57427F3EXAMPLE REST.GET.VERSIONING - \"GET /awsexamplebucket?versioning HTTP/1.1\" 200 - 113 - 7 - \"-\" \"S3Console/0.4\" - s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234= SigV2 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader awsexamplebucket.s3.amazonaws.com TLSV1.1"

	date := time.Unix(1549411238, 0).UTC()
	expectedEvent := &S3ServerAccess{
		BucketOwner:        aws.String("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"),
		Bucket:             aws.String("awsexamplebucket"),
		Time:               (*timestamp.RFC3339)(&date),
		RemoteIP:           aws.String("192.0.2.3"),
		Requester:          aws.String("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"),
		RequestID:          aws.String("3E57427F3EXAMPLE"),
		Operation:          aws.String("REST.GET.VERSIONING"),
		RequestURI:         aws.String("GET /awsexamplebucket?versioning HTTP/1.1"),
		HTTPStatus:         aws.Int(200),
		BytesSent:          aws.Int(113),
		TotalTime:          aws.Int(7),
		UserAgent:          aws.String("S3Console/0.4"),
		HostID:             aws.String("s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234="),
		SignatureVersion:   aws.String("SigV2"),
		CipherSuite:        aws.String("ECDHE-RSA-AES128-GCM-SHA256"),
		AuthenticationType: aws.String("AuthHeader"),
		HostHeader:         aws.String("awsexamplebucket.s3.amazonaws.com"),
		TLSVersion:         aws.String("TLSV1.1"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.S3ServerAccess")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&date)
	expectedEvent.AppendAnyIPAddresses("192.0.2.3")

	checkS3AccessLog(t, log, expectedEvent)
}

func TestS3AccessLogGetHttpNotFound(t *testing.T) {
	//nolint:lll
	log := `79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket [06/Feb/2019:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be A1206F460EXAMPLE REST.GET.BUCKETPOLICY - "GET /awsexamplebucket?policy HTTP/1.1" 404 NoSuchBucketPolicy 297 - 38 - "-" "S3Console/0.4" - BNaBsXZQQDbssi6xMBdBU2sLt+Yf5kZDmeBUP35sFoKa3sLLeMC78iwEIWxs99CRUrbS4n11234= SigV2 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader awsexamplebucket.s3.amazonaws.com TLSV1.1`

	date := time.Unix(1549411238, 0).UTC()
	expectedEvent := &S3ServerAccess{
		BucketOwner:        aws.String("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"),
		Bucket:             aws.String("awsexamplebucket"),
		Time:               (*timestamp.RFC3339)(&date),
		RemoteIP:           aws.String("192.0.2.3"),
		Requester:          aws.String("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"),
		RequestID:          aws.String("A1206F460EXAMPLE"),
		Operation:          aws.String("REST.GET.BUCKETPOLICY"),
		RequestURI:         aws.String("GET /awsexamplebucket?policy HTTP/1.1"),
		HTTPStatus:         aws.Int(404),
		ErrorCode:          aws.String("NoSuchBucketPolicy"),
		BytesSent:          aws.Int(297),
		TotalTime:          aws.Int(38),
		UserAgent:          aws.String("S3Console/0.4"),
		HostID:             aws.String("BNaBsXZQQDbssi6xMBdBU2sLt+Yf5kZDmeBUP35sFoKa3sLLeMC78iwEIWxs99CRUrbS4n11234="),
		SignatureVersion:   aws.String("SigV2"),
		CipherSuite:        aws.String("ECDHE-RSA-AES128-GCM-SHA256"),
		AuthenticationType: aws.String("AuthHeader"),
		HostHeader:         aws.String("awsexamplebucket.s3.amazonaws.com"),
		TLSVersion:         aws.String("TLSV1.1"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.S3ServerAccess")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&date)
	expectedEvent.AppendAnyIPAddresses("192.0.2.3")

	checkS3AccessLog(t, log, expectedEvent)
}

func TestS3AccessLogPutHttpOK(t *testing.T) {
	//nolint:lll
	log := `79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket [06/Feb/2019:00:00:38 +0000] 192.0.2.3 arn:aws:sts::123456789012:assumed-role/PantherLogProcessingRole/1579693334126446707 DD6CC733AEXAMPLE REST.PUT.OBJECT s3-dg.pdf "PUT /awsexamplebucket/s3-dg.pdf HTTP/1.1" 200 - - 4406583 41754 28 "-" "S3Console/0.4" - 10S62Zv81kBW7BB6SX4XJ48o6kpcl6LPwEoizZQQxJd5qDSCTLX0TgS37kYUBKQW3+bPdrg1234= SigV4 ECDHE-RSA-AES128-SHA AuthHeader awsexamplebucket.s3.amazonaws.com TLSV1.1`

	date := time.Unix(1549411238, 0).UTC()
	expectedEvent := &S3ServerAccess{
		BucketOwner:        aws.String("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"),
		Bucket:             aws.String("awsexamplebucket"),
		Key:                aws.String("s3-dg.pdf"),
		ObjectSize:         aws.Int(4406583),
		Time:               (*timestamp.RFC3339)(&date),
		RemoteIP:           aws.String("192.0.2.3"),
		Requester:          aws.String("arn:aws:sts::123456789012:assumed-role/PantherLogProcessingRole/1579693334126446707"),
		RequestID:          aws.String("DD6CC733AEXAMPLE"),
		Operation:          aws.String("REST.PUT.OBJECT"),
		RequestURI:         aws.String("PUT /awsexamplebucket/s3-dg.pdf HTTP/1.1"),
		HTTPStatus:         aws.Int(200),
		TotalTime:          aws.Int(41754),
		TurnAroundTime:     aws.Int(28),
		UserAgent:          aws.String("S3Console/0.4"),
		HostID:             aws.String("10S62Zv81kBW7BB6SX4XJ48o6kpcl6LPwEoizZQQxJd5qDSCTLX0TgS37kYUBKQW3+bPdrg1234="),
		SignatureVersion:   aws.String("SigV4"),
		CipherSuite:        aws.String("ECDHE-RSA-AES128-SHA"),
		AuthenticationType: aws.String("AuthHeader"),
		HostHeader:         aws.String("awsexamplebucket.s3.amazonaws.com"),
		TLSVersion:         aws.String("TLSV1.1"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.S3ServerAccess")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&date)
	expectedEvent.AppendAnyIPAddresses("192.0.2.3")
	expectedEvent.AppendAnyAWSARNs("arn:aws:sts::123456789012:assumed-role/PantherLogProcessingRole/1579693334126446707")

	checkS3AccessLog(t, log, expectedEvent)
}

func TestS3AccessLogPutHttpOKExtraFields(t *testing.T) {
	//nolint:lll
	log := `79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket [06/Feb/2019:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be DD6CC733AEXAMPLE REST.PUT.OBJECT s3-dg.pdf "PUT /awsexamplebucket/s3-dg.pdf HTTP/1.1" 200 - - 4406583 41754 28 "-" "S3Console/0.4" - 10S62Zv81kBW7BB6SX4XJ48o6kpcl6LPwEoizZQQxJd5qDSCTLX0TgS37kYUBKQW3+bPdrg1234= SigV4 ECDHE-RSA-AES128-SHA AuthHeader awsexamplebucket.s3.amazonaws.com TLSV1.1 test1 test2`

	date := time.Unix(1549411238, 0).UTC()
	expectedEvent := &S3ServerAccess{
		BucketOwner:        aws.String("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"),
		Bucket:             aws.String("awsexamplebucket"),
		Key:                aws.String("s3-dg.pdf"),
		ObjectSize:         aws.Int(4406583),
		Time:               (*timestamp.RFC3339)(&date),
		RemoteIP:           aws.String("192.0.2.3"),
		Requester:          aws.String("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"),
		RequestID:          aws.String("DD6CC733AEXAMPLE"),
		Operation:          aws.String("REST.PUT.OBJECT"),
		RequestURI:         aws.String("PUT /awsexamplebucket/s3-dg.pdf HTTP/1.1"),
		HTTPStatus:         aws.Int(200),
		TotalTime:          aws.Int(41754),
		TurnAroundTime:     aws.Int(28),
		UserAgent:          aws.String("S3Console/0.4"),
		HostID:             aws.String("10S62Zv81kBW7BB6SX4XJ48o6kpcl6LPwEoizZQQxJd5qDSCTLX0TgS37kYUBKQW3+bPdrg1234="),
		SignatureVersion:   aws.String("SigV4"),
		CipherSuite:        aws.String("ECDHE-RSA-AES128-SHA"),
		AuthenticationType: aws.String("AuthHeader"),
		HostHeader:         aws.String("awsexamplebucket.s3.amazonaws.com"),
		TLSVersion:         aws.String("TLSV1.1"),
		AdditionalFields:   []string{"test1", "test2"},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.S3ServerAccess")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&date)
	expectedEvent.AppendAnyIPAddresses("192.0.2.3")

	checkS3AccessLog(t, log, expectedEvent)
}

func TestS3AccessLogExpireNoHttpStatusObject(t *testing.T) {
	//nolint:lll
	log := `e45ff2803a4a73e13cca79d315b9aed3cf228184ab5c07725da3feaca1db2c98 panther-s3-logs-012345678901-us-east-1 [06/Feb/2019:00:00:38 +0000] - AmazonS3 128E87669E4C15FA S3.EXPIRE.OBJECT panther-s3-logs-012345678901-us-east-1/2020-01-11-22-33-30-23B392B734E22958 "-" - - - 3922 - - "-" "-" DkKg9NTmHopKgqKMcgjFyf4oujClO4J1 JFLmDHDLlTpiqmG5NECMOIsZfzN2Mki0OqHGVbsP20tAVq3176HcY0/F8Y9ONTth - - - - -`

	date := time.Unix(1549411238, 0).UTC()
	expectedEvent := &S3ServerAccess{
		BucketOwner: aws.String("e45ff2803a4a73e13cca79d315b9aed3cf228184ab5c07725da3feaca1db2c98"),
		Bucket:      aws.String("panther-s3-logs-012345678901-us-east-1"),
		Key:         aws.String("panther-s3-logs-012345678901-us-east-1/2020-01-11-22-33-30-23B392B734E22958"),
		ObjectSize:  aws.Int(3922),
		Time:        (*timestamp.RFC3339)(&date),
		Requester:   aws.String("AmazonS3"),
		RequestID:   aws.String("128E87669E4C15FA"),
		Operation:   aws.String("S3.EXPIRE.OBJECT"),
		HostID:      aws.String("JFLmDHDLlTpiqmG5NECMOIsZfzN2Mki0OqHGVbsP20tAVq3176HcY0/F8Y9ONTth"),
		VersionID:   aws.String("DkKg9NTmHopKgqKMcgjFyf4oujClO4J1"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.S3ServerAccess")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&date)

	checkS3AccessLog(t, log, expectedEvent)
}

func TestS3ServerAccessLogType(t *testing.T) {
	parser := &S3ServerAccessParser{}
	require.Equal(t, "AWS.S3ServerAccess", parser.LogType())
}

func checkS3AccessLog(t *testing.T, log string, expectedEvent *S3ServerAccess) {
	parser := &S3ServerAccessParser{}
	events := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events)
}
