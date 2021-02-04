// Package clients builds and caches connections to AWS and Panther services.
package clients

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/tools/mage/logger"
)

// NOTE: This file is deprecated - use AWS SDK v2 for new code

const (
	maxRetries = 20 // try very hard, avoid throttles

	UsersAPI = "panther-users-api"
)

var (
	log = logger.Build("")

	// Cache all of these privately to force lazy evaluation.
	awsSession *session.Session
	accountID  string

	cfnClient    *cloudformation.CloudFormation
	lambdaClient *lambda.Lambda
	s3Client     *s3.S3
	stsClient    *sts.STS
)

// Build the AWS session from credentials - subsequent calls return the cached result.
func getSession() *session.Session {
	if awsSession != nil {
		return awsSession
	}

	// Build a new session if it doesn't exist yet or the region changed.

	config := aws.NewConfig().WithMaxRetries(maxRetries)

	var err error
	awsSession, err = session.NewSession(config)
	if err != nil {
		log.Fatalf("failed to create AWS session: %v", err)
	}
	if aws.StringValue(awsSession.Config.Region) == "" {
		log.Fatalf("no region specified, set AWS_REGION or AWS_DEFAULT_REGION")
	}

	// Load and cache credentials now so we can report a meaningful error
	creds, err := awsSession.Config.Credentials.Get()
	if err != nil {
		if awsutils.IsAnyError(err, "NoCredentialProviders") {
			log.Fatalf("no AWS credentials found, set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
		log.Fatalf("failed to load AWS credentials: %v", err)
	}

	log.Debugw("loaded AWS credentials",
		"provider", creds.ProviderName,
		"region", awsSession.Config.Region,
		"accessKeyId", creds.AccessKeyID)
	return awsSession
}

// Returns the current AWS region.
func Region() string {
	return *getSession().Config.Region
}

// Returns the current AWS account ID - subsequent calls return the cached result.
func AccountID() string {
	if accountID == "" {
		identity, err := STS().GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			log.Fatalf("failed to get caller identity: %v", err)
		}
		accountID = *identity.Account
	}

	return accountID
}

func Cfn() *cloudformation.CloudFormation {
	if cfnClient == nil {
		cfnClient = cloudformation.New(getSession())
	}
	return cfnClient
}

func Lambda() *lambda.Lambda {
	if lambdaClient == nil {
		lambdaClient = lambda.New(getSession())
	}
	return lambdaClient
}

func S3() *s3.S3 {
	if s3Client == nil {
		s3Client = s3.New(getSession())
	}
	return s3Client
}

func STS() *sts.STS {
	if stsClient == nil {
		stsClient = sts.New(getSession())
	}
	return stsClient
}
