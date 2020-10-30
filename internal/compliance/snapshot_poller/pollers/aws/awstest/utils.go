package awstest

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
)

// Example output from the AWS API
var (
	ExampleTime, _             = time.Parse(time.RFC3339, "2019-04-02T17:16:30+00:00")
	ExampleIntegrationID       = aws.String("8e39aa9d-9823-4872-a1bd-40fd8795634b")
	ExampleAuthSource          = "arn:aws:iam::123456789012:role/PantherAuditRole"
	ExampleAuthSourceParsedARN = ParseExampleAuthSourceARN(ExampleAuthSource)
	ExampleAccountId           = aws.String("123456789012")
	ExampleRegion              = aws.String("us-west-2")
)

// ParseExampleAuthSourceARN returns a parsed Auth Source ARN
func ParseExampleAuthSourceARN(arnToParse string) arn.ARN {
	parsedArn, err := arn.Parse(arnToParse)
	if err != nil {
		return arn.ARN{}
	}

	return parsedArn
}
