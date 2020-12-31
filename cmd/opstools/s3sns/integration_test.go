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
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/cmd/opstools/testutils"
)

const (
	topicPrefix = "panther-test-s3sns"
	s3Prefix    = "logs/aws_vpcflow" // we expect there to some of these for the test to succeed
	concurrency = 10
)

var (
	integrationTest bool
	account         string
	awsSession      *session.Session
	s3Client        *s3.S3
	snsClient       *sns.SNS

	s3Bucket string
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession())
		s3Client = s3.New(awsSession)
		snsClient = sns.New(awsSession)

		identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			panic(err)
		}
		account = *identity.Account

		// get processed log bucket
		cfnClient := cloudformation.New(awsSession)
		response, err := cfnClient.DescribeStacks(
			&cloudformation.DescribeStacksInput{StackName: aws.String("panther-log-analysis")})
		if err != nil {
			panic(err.Error())
		}
		for _, param := range response.Stacks[0].Parameters {
			if aws.StringValue(param.ParameterKey) == "ProcessedDataBucket" {
				s3Bucket = *param.ParameterValue
			}
		}
	}
	os.Exit(m.Run())
}

func TestIntegrationS3SNS(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	// check that the number files sent matches what was listed, lookup attributes

	topicName := topicPrefix + "-topic"

	numberOfFiles, err := testutils.CountObjectsInBucket(s3Client, s3Bucket, s3Prefix)
	require.NoError(t, err)
	require.Greater(t, numberOfFiles, 0, "no data files, wait a bit then run again")

	createTopicOutput, err := testutils.CreateTopic(snsClient, topicName)
	require.NoError(t, err)

	input := &Input{
		Logger:      opstools.MustBuildLogger(true),
		Session:     awsSession,
		Account:     account,
		S3Path:      "s3://" + s3Bucket + "/" + s3Prefix,
		S3Region:    *awsSession.Config.Region,
		Topic:       topicName,
		Attributes:  true,
		Concurrency: concurrency,
	}
	err = S3SNS(context.TODO(), input)
	require.NoError(t, err)
	assert.Equal(t, numberOfFiles, (int)(input.Stats.NumFiles))

	err = testutils.DeleteTopic(snsClient, *createTopicOutput.TopicArn)
	assert.NoError(t, err)
}
