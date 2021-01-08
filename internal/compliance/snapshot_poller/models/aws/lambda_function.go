package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import "github.com/aws/aws-sdk-go/service/lambda"

const (
	LambdaFunctionSchema = "AWS.Lambda.Function"
)

// LambdaFunction contains all the information about an Lambda Function
type LambdaFunction struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from lambda.FunctionConfiguration
	CodeSha256       *string
	CodeSize         *int64
	DeadLetterConfig *lambda.DeadLetterConfig
	Description      *string
	Environment      *lambda.EnvironmentResponse
	Handler          *string
	KMSKeyArn        *string
	LastModified     *string
	Layers           []*lambda.Layer
	MasterArn        *string
	MemorySize       *int64
	RevisionId       *string
	Role             *string
	Runtime          *string
	Timeout          *int64
	TracingConfig    *lambda.TracingConfigResponse
	Version          *string
	VpcConfig        *lambda.VpcConfigResponse

	// Additional fields
	Policy *lambda.GetPolicyOutput
}
