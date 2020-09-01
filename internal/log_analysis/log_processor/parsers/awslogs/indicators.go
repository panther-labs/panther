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
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

const SizeAccountID = 12

var rxAccountID = regexp.MustCompile(`^\d{12}$`)

func init() {
	pantherlog.MustRegisterScannerFunc("aws_arn", ScanARN,
		pantherlog.FieldAWSARN,
		pantherlog.FieldAWSInstanceID,
		pantherlog.FieldAWSAccountID,
	)
	pantherlog.MustRegisterScannerFunc("aws_account_id", ScanAccountID, pantherlog.FieldAWSAccountID)
	pantherlog.MustRegisterScannerFunc("aws_instance_id", ScanInstanceID, pantherlog.FieldAWSInstanceID)
	pantherlog.MustRegisterScannerFunc("aws_tag", ScanTag, pantherlog.FieldAWSTag)
}

func ScanARN(w pantherlog.ValueWriter, input string) {
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
	w.WriteValues(pantherlog.FieldAWSARN, input)
	w.WriteValues(pantherlog.FieldAWSAccountID, arn.AccountID)
	// instanceId: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policy-structure.html#EC2_ARN_Format
	if !strings.HasPrefix(input, "instance/") {
		return
	}
	if pos := strings.LastIndex(input, "/"); 0 <= pos && pos < len(input) { // not if ends in "/"
		instanceID := input[pos:]
		if len(instanceID) > 0 {
			ScanInstanceID(w, instanceID[1:])
		}
	}
}

func ScanTag(w pantherlog.ValueWriter, input string) {
	w.WriteValues(pantherlog.FieldAWSTag, input)
}

func ScanAccountID(w pantherlog.ValueWriter, input string) {
	if len(input) == SizeAccountID && rxAccountID.MatchString(input) {
		w.WriteValues(pantherlog.FieldAWSAccountID, input)
	}
}

func ScanInstanceID(w pantherlog.ValueWriter, input string) {
	if strings.HasPrefix(input, "i-") {
		w.WriteValues(pantherlog.FieldAWSInstanceID, input)
	}
}
