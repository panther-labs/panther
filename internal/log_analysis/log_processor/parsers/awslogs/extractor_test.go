package awslogs

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
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/extract"
)

func TestAWSExtractor(t *testing.T) {
	event := AWSPantherLog{}
	// add interesting fragments as new extractions are implemented
	json := jsoniter.RawMessage(awsRawMessageSample)

	expectedEvent := AWSPantherLog{}
	expectedEvent.AppendAnyAWSARNs(
		"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail",
		"arn:aws:iam::123456789012:instance-profile/ArnLike",
		"arn:aws:iam::123456789012:instance-profile/EC2Dev",
		"arn:aws:ec2:region:111122223333:instance/i-0072230f74b3a798e",
		"arn:aws:ec2:region:111122223333:instance/",
	)
	expectedEvent.AppendAnyAWSInstanceIds("i-081de1d7604b11e4a", "i-0072230f74b3a798e" /* from ARN */)
	expectedEvent.AppendAnyAWSAccountIds("123456789012", "888888888888" /* from ARN */, "111122223333" /* from ARN */)
	expectedEvent.AppendAnyIPAddress("54.152.215.140")
	expectedEvent.AppendAnyIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	expectedEvent.AppendAnyIPAddress("172.31.81.237")
	expectedEvent.AppendAnyIPAddress("151.80.19.228")
	expectedEvent.AppendAnyAWSTags("tag1:val1")
	expectedEvent.AppendAnyDomainNames(
		"ip-172-31-81-237.ec2.internal",
		"ec2-54-152-215-140.compute-1.amazonaws.com",
		"GeneratedFindingDomainName",
	)

	extract.Extract(&json, NewAWSExtractor(&event))

	require.Equal(t, expectedEvent, event)
}
