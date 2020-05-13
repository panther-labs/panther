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

	// Creates error/warn/memory metric filters on a Lambda function's CloudWatch log group.
	//
	// Parameters:
	//     LambdaRuntime: string ("Go" or "Python", default: "Go")
	//     LogGroupName:  string (required)
	// Outputs: None
	// PhysicalId: custom:metric-filters:$LOG_GROUP_NAME
	"Custom::LambdaMetricFilters": customLambdaMetricFilters,
}
