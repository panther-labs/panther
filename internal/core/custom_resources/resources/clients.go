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
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/acm/acmiface"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/guardduty/guarddutyiface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
)

var (
	env envConfig

	awsSession = session.Must(session.NewSession(aws.NewConfig().WithMaxRetries(10)))

	acmClient            acmiface.ACMAPI                                         = acm.New(awsSession)
	cloudWatchClient     cloudwatchiface.CloudWatchAPI                           = cloudwatch.New(awsSession)
	cloudWatchLogsClient cloudwatchlogsiface.CloudWatchLogsAPI                   = cloudwatchlogs.New(awsSession)
	cognitoClient        cognitoidentityprovideriface.CognitoIdentityProviderAPI = cognitoidentityprovider.New(awsSession)
	dynamoClient         dynamodbiface.DynamoDBAPI                               = dynamodb.New(awsSession)
	ecrClient            ecriface.ECRAPI                                         = ecr.New(awsSession)
	glueClient           glueiface.GlueAPI                                       = glue.New(awsSession)
	endpointResolver     endpoints.Resolver                                      = endpoints.DefaultResolver()
	guardDutyClient      guarddutyiface.GuardDutyAPI                             = guardduty.New(awsSession)
	iamClient            iamiface.IAMAPI                                         = iam.New(awsSession)
	lambdaClient         lambdaiface.LambdaAPI                                   = lambda.New(awsSession)
	s3Client             s3iface.S3API                                           = s3.New(awsSession)
	sqsClient            sqsiface.SQSAPI                                         = sqs.New(awsSession)
	logtypesAPI          logtypesapi.LogTypesAPILambdaClient                     = logtypesapi.LogTypesAPILambdaClient{
		LambdaName: logtypesapi.LambdaName,
		LambdaAPI:  lambdaClient,
	}

	accountDescription string
)

type envConfig struct {
	AccountID          string `required:"true" split_words:"true"`
	CompanyDisplayName string `required:"true" split_words:"true"`
}

func Setup() {
	envconfig.MustProcess("", &env)

	accountDescription = fmt.Sprintf("%s (%s:%s)",
		env.CompanyDisplayName, env.AccountID, *awsSession.Config.Region)
}
