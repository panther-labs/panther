package awsathena

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
