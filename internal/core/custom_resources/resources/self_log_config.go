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
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/s3"
)

type SelfLogConfigProperties struct {
	AuditLogsBucket       string `validate:"required"`
	EnableGuardDuty       bool   `json:",string"`
	GuardDutyDetectorID   string // can be blank if EnableGuardDuty=false
	GuardDutyKmsKeyArn    string // can be blank if EnableGuardDuty=false
	LogProcessingTopicArn string `validate:"required"`
}

func customSelfLogConfig(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props SelfLogConfigProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		return "custom:self-log-config:singleton", nil, configureLogProcessingUsingAPIs(props)

	default:
		// ignore deletes
		return event.PhysicalResourceID, nil, nil
	}
}

func configureLogProcessingUsingAPIs(props SelfLogConfigProperties) error {
	// currently GuardDuty does not support this in CF
	if err := configureLogProcessingGuardDuty(props); err != nil {
		return err
	}

	// configure notifications on the audit bucket, cannot be done via CF
	input := &s3.PutBucketNotificationConfigurationInput{
		Bucket: &props.AuditLogsBucket,
		NotificationConfiguration: &s3.NotificationConfiguration{
			TopicConfigurations: []*s3.TopicConfiguration{
				{
					Events: []*string{
						aws.String(s3.EventS3ObjectCreated),
					},
					TopicArn: &props.LogProcessingTopicArn,
				},
			},
		},
	}
	_, err := getS3Client().PutBucketNotificationConfiguration(input)
	if err != nil {
		return fmt.Errorf("failed to add s3 notifications to %s from %s: %v",
			props.AuditLogsBucket, props.LogProcessingTopicArn, err)
	}

	return nil
}

func configureLogProcessingGuardDuty(props SelfLogConfigProperties) error {
	if !props.EnableGuardDuty {
		return nil
	}

	publishInput := &guardduty.CreatePublishingDestinationInput{
		DetectorId:      &props.GuardDutyDetectorID,
		DestinationType: aws.String("S3"),
		DestinationProperties: &guardduty.DestinationProperties{
			DestinationArn: aws.String("arn:aws:s3:::" + props.AuditLogsBucket),
			KmsKeyArn:      &props.GuardDutyKmsKeyArn,
		},
	}
	_, err := getGuardDutyClient().CreatePublishingDestination(publishInput)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to configure Guard Duty detector %s to use bucket %s with kms key %s: %v",
			props.GuardDutyDetectorID, props.AuditLogsBucket, props.GuardDutyKmsKeyArn, err)
	}

	return nil
}
