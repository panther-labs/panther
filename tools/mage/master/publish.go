package master

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
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/tools/mage/util"
)

func publishToRegion(log *zap.SugaredLogger, version, region string) error {
	log.Infof("publishing to %s", region)
	// We need a different client for each region, so we don't use the global AWS clients pkg here.
	awsSession := session.Must(session.NewSession(
		aws.NewConfig().WithMaxRetries(10).WithRegion(region)))

	bucket := util.PublicAssetsBucket()
	s3Key := fmt.Sprintf("v%s/panther.yml", version)
	s3URL := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucket, s3Key)

	// Check if this version already exists - it's easy to forget to update the version
	// in the template file and we don't want to overwrite a previous version.
	_, err := s3.New(awsSession).HeadObject(&s3.HeadObjectInput{Bucket: &bucket, Key: &s3Key})
	if err == nil {
		return fmt.Errorf("%s already exists", s3URL)
	}
	if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != "NotFound" {
		// Some error other than 'not found'
		return fmt.Errorf("failed to describe %s : %v", s3URL, err)
	}

	// Publish S3 assets and ECR docker image
	pkg, err := Package(log, region, bucket, version, fmt.Sprintf(publicImageRepository, region))
	if err != nil {
		return err
	}

	// Upload final packaged template
	if _, err := util.UploadFileToS3(log, pkg, bucket, s3Key); err != nil {
		return fmt.Errorf("failed to upload %s : %v", s3URL, err)
	}

	log.Infof("successfully published %s", s3URL)
	return nil
}
