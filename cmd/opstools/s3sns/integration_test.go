package s3sns

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
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/cmd/opstools/testutils"
)

const (
	topicPrefix   = "panther-test-s3sns"
	s3Bucket        = "panther-public-cloudformation-templates" // this is a public Panther bucket with CF files we can use
	s3Region      = "us-west-2"                                     // region of above bucket
	concurrency   = 10
)

var (
	integrationTest bool
	account         string
	awsSession      *session.Session
	s3Client        *s3.S3
	snsClient       *sns.SNS
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession(aws.NewConfig().WithRegion(s3Region)))
		s3Client = s3.New(awsSession)
		snsClient = sns.New(awsSession)

		identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			panic(err)
		}
		account = *identity.Account
	}
	os.Exit(m.Run())
}

func TestIntegrationS3SNS(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	// check that the number files sent matches what was listed

	topicName := topicPrefix + "-topic"

	numberOfFiles, err := testutils.CountObjectsInBucket(s3Client, s3Bucket)
	require.NoError(t, err)

	createTopicOutput, err := testutils.CreateTopic(snsClient, topicName)
	require.NoError(t, err)

	stats := &Stats{}
	err = S3Topic(awsSession, account, "s3://" + s3Bucket, s3Region, topicName, false, concurrency, 0, stats)
	require.NoError(t, err)
	assert.Equal(t, numberOfFiles, (int)(stats.NumFiles))

	err = testutils.DeleteTopic(snsClient, *createTopicOutput.TopicArn)
	assert.NoError(t, err)
}
