package resources

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
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/acm/acmiface"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/guardduty/guarddutyiface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

// Lazily build all AWS clients - each Lambda invocation usually needs at most 1 of these
var (
	awsSession *session.Session

	acmClient            acmiface.ACMAPI
	cloudFormationClient cloudformationiface.CloudFormationAPI
	cloudWatchClient     cloudwatchiface.CloudWatchAPI
	cloudWatchLogsClient cloudwatchlogsiface.CloudWatchLogsAPI
	cognitoClient        cognitoidentityprovideriface.CognitoIdentityProviderAPI
	guardDutyClient      guarddutyiface.GuardDutyAPI
	iamClient            iamiface.IAMAPI
	lambdaClient         lambdaiface.LambdaAPI
	s3Client             s3iface.S3API
)

func getSession() *session.Session {
	if awsSession == nil {
		awsSession = session.Must(session.NewSession(aws.NewConfig().WithMaxRetries(10)))
	}
	return awsSession
}

func getAcmClient() acmiface.ACMAPI {
	if acmClient == nil {
		acmClient = acm.New(getSession())
	}
	return acmClient
}

func getCloudFormationClient() cloudformationiface.CloudFormationAPI {
	if cloudFormationClient == nil {
		cloudFormationClient = cloudformation.New(getSession())
	}
	return cloudFormationClient
}

func getCloudWatchClient() cloudwatchiface.CloudWatchAPI {
	if cloudWatchClient == nil {
		cloudWatchClient = cloudwatch.New(getSession())
	}
	return cloudWatchClient
}

func getCloudWatchLogsClient() cloudwatchlogsiface.CloudWatchLogsAPI {
	if cloudWatchLogsClient == nil {
		cloudWatchLogsClient = cloudwatchlogs.New(getSession())
	}
	return cloudWatchLogsClient
}

func getCognitoClient() cognitoidentityprovideriface.CognitoIdentityProviderAPI {
	if cognitoClient == nil {
		cognitoClient = cognitoidentityprovider.New(getSession())
	}
	return cognitoClient
}

func getGuardDutyClient() guarddutyiface.GuardDutyAPI {
	if guardDutyClient == nil {
		guardDutyClient = guardduty.New(getSession())
	}
	return guardDutyClient
}

func getIamClient() iamiface.IAMAPI {
	if iamClient == nil {
		iamClient = iam.New(getSession())
	}
	return iamClient
}

func getLambdaClient() lambdaiface.LambdaAPI {
	if lambdaClient == nil {
		lambdaClient = lambda.New(getSession())
	}
	return lambdaClient
}

func getS3Client() s3iface.S3API {
	if s3Client == nil {
		s3Client = s3.New(getSession())
	}
	return s3Client
}
