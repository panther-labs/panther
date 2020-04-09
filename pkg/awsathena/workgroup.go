package awsathena

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
)

// WorkgroupAssociateS3 associates the S3 bucket with named workgroup
func WorkgroupAssociateS3(sess *session.Session, name, s3Bucket string) (err error) {
	athenaSession := athena.New(sess)
	input := athena.UpdateWorkGroupInput{
		ConfigurationUpdates: &athena.WorkGroupConfigurationUpdates{
			ResultConfigurationUpdates: &athena.ResultConfigurationUpdates{
				OutputLocation: aws.String("s3://" + s3Bucket),
			},
		},
		WorkGroup: aws.String(name),
	}
	_, err = athenaSession.UpdateWorkGroup(&input)
	return err
}
