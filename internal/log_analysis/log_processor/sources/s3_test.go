package sources

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

	"github.com/stretchr/testify/require"
)

func TestParseCloudTrailNotification(t *testing.T) {
	notification := "{\"s3Bucket\": \"testbucket\", \"s3ObjectKey\": [\"key1\",\"key2\"]}"
	expectedOutput := []*S3ObjectInfo{
		{
			S3Bucket:    "testbucket",
			S3ObjectKey: "key1",
		},
		{
			S3Bucket:    "testbucket",
			S3ObjectKey: "key2",
		},
	}
	s3Objects, err := ParseNotification(notification)
	require.NoError(t, err)
	require.Equal(t, expectedOutput, s3Objects)
}

func TestParseS3Notification(t *testing.T) {
	//nolint:lll
	notification := "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"1970-01-01T00:00:00.000Z\"," +
		"\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AIDAJDPLRKLG7UEXAMPLE\"},\"requestParameters\":{\"sourceIPAddress\":\"127.0.0.1\"}," +
		"\"responseElements\":{\"x-amz-request-id\":\"C3D13FE58DE4C810\",\"x-amz-id-2\":\"FMyUVURIY8/IgAtTv8xRjskZQpcIZ9KG4V5Wp6S7S/JRWeUWerMUE5JgHvANOjpD\"}," +
		"\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"testConfigRule\"," +
		"\"bucket\":{\"name\":\"mybucket\",\"ownerIdentity\":{\"principalId\":\"A3NL1KOZZKExample\"},\"arn\":\"arn:aws:s3:::mybucket\"},\"object\":{\"key\":\"key1\",\"size\":1024," +
		"\"eTag\":\"d41d8cd98f00b204e9800998ecf8427e\",\"versionId\":\"096fKKXTRTtl3on89fVO.nfljtsv6qko\",\"sequencer\":\"0055AED6DCD90281E5\"}}}]}"
	expectedOutput := []*S3ObjectInfo{
		{
			S3Bucket:    "mybucket",
			S3ObjectKey: "key1",
		},
	}
	s3Objects, err := ParseNotification(notification)
	require.NoError(t, err)
	require.Equal(t, expectedOutput, s3Objects)
}

func TestParseTestS3Notification(t *testing.T) {
	//nolint:lll
	notification := "{\"Service\":\"Amazon S3\",\"Event\":\"s3:TestEvent\",\"Time\":\"2020-01-21T14:17:54.420Z\",\"Bucket\":\"test-bucket\"," +
		"\"RequestId\":\"0D79B9C057838DEA\",\"HostId\":\"6HTLml3u1UbsYgjuzueCQApRHOfpRM5yJ+nTZCveOMejyM7iB4Pg8RESbVAU5nHjduW+QoeK+UA=\"}"

	s3Objects, err := ParseNotification(notification)
	require.NoError(t, err)
	require.Equal(t, 0, len(s3Objects))
}
