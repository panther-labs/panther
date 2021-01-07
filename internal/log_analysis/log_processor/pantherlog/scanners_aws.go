package pantherlog

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
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
)

func ScanARN(w ValueWriter, input string) {
	// value based matching
	if !strings.HasPrefix(input, "arn:") {
		return
	}
	// ARNs may contain an embedded account id as well as interesting resources
	// See: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
	// Formats:
	//  arn:partition:service:region:account-id:resource-id
	//  arn:partition:service:region:account-id:resource-type/resource-id
	//  arn:partition:service:region:account-id:resource-type:resource-id
	arn, err := arn.Parse(input)
	if err != nil {
		return
	}
	w.WriteValues(FieldAWSARN, input)
	ScanAWSAccountID(w, arn.AccountID)

	// instanceId: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policy-structure.html#EC2_ARN_Format
	if !strings.HasPrefix(arn.Resource, "instance/") {
		return
	}
	if pos := strings.LastIndex(arn.Resource, "/"); 0 <= pos && pos < len(arn.Resource) { // not if ends in "/"
		instanceID := arn.Resource[pos:]
		if len(instanceID) > 0 {
			ScanAWSInstanceID(w, instanceID[1:])
		}
	}
}

func ScanAWSTag(w ValueWriter, input string) {
	w.WriteValues(FieldAWSTag, input)
}

func ScanAWSAccountID(w ValueWriter, input string) {
	if isAWSAccountID(input) {
		w.WriteValues(FieldAWSAccountID, input)
	}
}

func isAWSAccountID(value string) bool {
	const sizeAccountID = 12
	if len(value) != sizeAccountID {
		return false
	}
	for i := 0; 0 <= i && i < sizeAccountID; i++ {
		if isDigit := '0' <= value[i] && value[i] <= '9'; !isDigit {
			return false
		}
	}
	return true
}

func ScanAWSInstanceID(w ValueWriter, input string) {
	if strings.HasPrefix(input, "i-") {
		w.WriteValues(FieldAWSInstanceID, input)
	}
}
