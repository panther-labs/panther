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
	"github.com/aws/aws-lambda-go/cfn"
)

// CustomResources map type names to their respective handler functions.
var CustomResources = map[string]cfn.CustomResourceFunction{
	// CloudWatch alarms for API Gateway 5XX errors and high integration latency.
	//
	// Parameters:
	//     ApiName:            string (required)
	//     AlarmTopicArn:      string (required)
	//     ErrorThreshold:     int (default: 0)
	//     LatencyThresholdMs: float (default: 1000)
	// Outputs: None
	// PhysicalId: custom:alarms:api:$API_NAME
	"Custom::ApiGatewayAlarms": customAPIGatewayAlarms,

	// CloudWatch alarms for AppSync 4XX and 5XX errors
	//
	// Parameters:
	//     ApiId:                string (required)
	//     ApiName:              string (required)
	//     AlarmTopicArn:        string (required)
	//     ClientErrorThreshold: int (default: 0)
	//     ServerErrorThreshold: int (default: 0)
	// Outputs: None
	// PhysicalId: custom:alarms:appsync:$API_ID
	"Custom::AppSyncAlarms": customAppSyncAlarms,

	// CloudWatch alarms for Dynamo errors, throttles, and latency
	//
	// Parameters:
	//     AlarmTopicArn:  string (required)
	//     TableName:      string (required)
	// Outputs: None
	// PhysicalId: custom:alarms:dynamodb:$TABLE_NAME
	"Custom::DynamoDBAlarms": customDynamoDBAlarms,

	// CloudWatch alarms for ELB errors, latency, and health
	//
	// Parameters:
	//     AlarmTopicArn:              string (required)
	//     LoadBalancerFriendlyName:   string (required)
	//     LoadBalancerFullName:       string (required)
	//     ClientErrorThreshold:       int (default: 0)
	//     LatencyThresholdSeconds:    float (default: 0.5)
	// Outputs: None
	// PhysicalId: custom:alarms:elb:$LOAD_BALANCER_FRIENDLY_NAME
	"Custom::ElbAlarms": customElbAlarms,

	// Creates a self-signed ACM or IAM server certificate.
	//
	// Parameters: None
	// Outputs:
	//     CertificateArn: ACM or IAM certificate arn
	// PhysicalId: (real certificate ARN)
	"Custom::Certificate": customCertificate,

	// Enforces MFA with TOTP as the only option.
	//
	// Parameters:
	//     UserPoolId: string (required)
	// Outputs: None
	// PhysicalId: custom:cognito-user-pool:$USER_POOL_ID:mfa
	//
	// Deleting this resource has no effect on the user pool.
	"Custom::CognitoUserPoolMfa": customCognitoUserPoolMfa,

	// Creates alarms for lambda errors, warning, throttles, duration, and memory
	//
	// Parameters:
	//     AlarmTopicArn:           string (required)
	//     FunctionName:            string (required)
	//
	//     FunctionMemoryMB:        int (default: 128)
	//     FunctionTimeoutSec:      int (default: 60)
	//
	//     LoggedErrorThreshold:    int (default: 0)
	//     LoggedWarnThreshold:     int (default: 25)
	//     ExecutionErrorThreshold: int (default: 0)
	//     ThrottleThreshold:       int (default: 5)
	// Outputs: None
	// PhysicalId: custom:alarms:lambda:$FUNCTION_NAME
	"Custom::LambdaAlarms": customLambdaAlarms,

	// Creates error/warn/memory metric filters on a Lambda function's CloudWatch log group.
	//
	// Parameters:
	//     LambdaRuntime: string ("Go" or "Python", default: "Go")
	//     LogGroupName:  string (required)
	// Outputs: None
	// PhysicalId: custom:metric-filters:$LOG_GROUP_NAME
	"Custom::LambdaMetricFilters": customLambdaMetricFilters,

	// Creates an alarm for failed step function executions
	//
	// Parameters:
	//     AlarmTopicArn:    string (required)
	//     StateMachineArn:  string (required)
	// Outputs: None
	// PhysicalId: custom:alarms:sfn:$STATE_MACHINE_NAME
	"Custom::StateMachineAlarms": customStateMachineAlarms,
}
