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
	// Install default Python rules/policies for a fresh deployment (singleton).
	//
	// Parameters:
	//     AnaylsisApiEndpoint: string (required)
	//     PackURLs:            list<string>
	// Outputs: None
	// PhysicalId: custom:analysis:init
	"Custom::AnalysisSet": customAnalysisSet,

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

	// Updates databases and table schemas in Glue
	//
	// Parameters:
	//    DeploymentId:  string (required)
	// Outputs: None
	// PhysicalId: custom:glue:update-log-processor-tables
	"Custom::UpdateLogProcessorTables": customUpdateLogTables,

	// Add a GuardDuty publishing destination
	//
	// Parameters = guardduty.CreatePublishingDestinationInput
	//    DetectorId:            string (required)
	//    DestinationType:       string (required)
	//    DestinationProperties:
	//        DestinationArn:    string (required)
	//        KmsKeyArn:         string
	// Outputs:
	//    DestinationId:         string
	// PhysicalId: custom:guardduty:destination:$DETECTOR_ID:$DESTINATION_ID
	"Custom::GuardDutyDestination": customGuardDutyDestination,

	// Creates alarms for lambda errors, warning, throttles, duration, and memory
	//
	// Parameters:
	//     AlarmTopicArn:           string (required)
	//     FunctionName:            string (required)
	//     FunctionMemoryMB:        int (required)
	//     FunctionTimeoutSec:      int (required)
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

	// Update Panther organization settings
	//
	// Parameters = organization-api/models/GeneralSettings
	//     DisplayName:           string
	//     Email:                 string
	//     ErrorReportingConsent: bool
	//     AnalyticsConsent:      bool
	// Outputs: None
	// PhysicalId: custom:panther-settings:singleton
	"Custom::PantherSettings": customPantherSettings,

	// Specifies a list of Lambda layers a Lambda function should attach.
	//
	// Parameters:
	//     Layers:
	//         - LayerArn      string
	//
	// The LayerArn parameter(s) above should be a full (versioned) layer ARN. If the version is
	// specified as LATEST, we look up the latest version of the layer and use that. If a specified
	// layer does not exist, it is skipped.
	//
	// Outputs: LayerArns - A list of versioned lambda layer ARNs for a lambda function to attach
	// PhysicalId: custom:lambda:layerattachment
	"Custom::LayerAttachment": customLayerAttachment,

	// Teardown Panther assets which aren't managed by CloudFormation.
	// This resource has no effect until it is deleted.
	//
	// Parameters:
	//     EcrRepoName: string
	// Outputs: None
	// PhysicalId: custom:panther-teardown:singleton
	"Custom::PantherTeardown": customPantherTeardown,

	// Invite a new user to Panther.
	// Updates and deletes to this resource will also be reflected in Panther.
	//
	// Parameters:
	//     GivenName:   string
	//     FamilyName:  string
	//     Email:       string (required)
	// PhysicalId: custom:panther-user:$USER_ID
	"Custom::PantherUser": customPantherUser,

	// Update notifications for an S3 bucket.
	//
	// Parameters = s3.PutBucketNotificationConfigurationInput
	//     Bucket:                      string (required)
	//     NotificationConfiguration:
	//         TopicConfigurations:
	//             - Events:            list<string>
	//               TopicArn:          string (required)
	// Outputs: None
	// PhysicalId: custom:s3bucketnotification:$BUCKET_NAME
	"Custom::S3BucketNotification": customS3BucketNotification,

	// Panther adds itself as a cloud security and/or log processing source.
	//
	// Parameters:
	//     AccountID:          string (required)
	//     AuditLogsBucket:    string (required)
	//     EnableCloudTrail:   bool (default: false)
	//     EnableGuardDuty:    bool (default: false)
	//     EnableS3AccessLogs: bool (default: false)
	// Outputs: None
	// PhysicalId: custom:self-registration:$ACCOUNT_ID
	"Custom::SelfRegistration": customSelfRegistration,

	// Creates an alarm for failed step function executions
	//
	// Parameters:
	//     AlarmTopicArn:    string (required)
	//     StateMachineArn:  string (required)
	// Outputs: None
	// PhysicalId: custom:alarms:sfn:$STATE_MACHINE_NAME
	"Custom::StateMachineAlarms": customStateMachineAlarms,

	// Creates an alarm for failed SNS notifications.
	//
	// Parameters:
	//     AlarmTopicArn:    string (required)
	//     TopicName:        string (required)
	// Outputs: None
	// PhysicalId: custom:alarms:sns:$TOPIC_NAME
	"Custom::SNSAlarms": customSNSAlarms,

	// Creates an alarm for high SQS age and entries in a DLQ
	//
	// Parameters:
	//     AlarmTopicArn:    string (required)
	//     QueueName:        string (required)
	//	   IsDLQ:            bool (default: false)
	// Outputs: None
	// PhysicalId: custom:alarms:sqs:$QUEUE_NAME
	"Custom::SQSAlarms": customSQSAlarms,

	// Updates managed schemas to match minimum required version
	//
	// Parameters: None
	// Outputs: None
	// PhysicalId: custom:schemas:managed
	"Custom::ManagedSchemas": customUpdateManagedSchemas,
}
