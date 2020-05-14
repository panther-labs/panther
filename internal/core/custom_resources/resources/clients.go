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
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// Lazily build all AWS clients - each Lambda invocation usually needs at most 1 of these
var (
	awsSession *session.Session

	acmClient            acmiface.ACMAPI
	cloudWatchClient     cloudwatchiface.CloudWatchAPI
	cloudWatchLogsClient cloudwatchlogsiface.CloudWatchLogsAPI
	cognitoClient        cognitoidentityprovideriface.CognitoIdentityProviderAPI
	iamClient            iamiface.IAMAPI
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

func getIamClient() iamiface.IAMAPI {
	if iamClient == nil {
		iamClient = iam.New(getSession())
	}
	return iamClient
}
