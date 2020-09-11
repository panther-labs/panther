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
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/mage/clean"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/setup"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Publish a new Panther release (Panther team only)
func Publish() error {
	log := logger.Build("[master:publish]")
	if err := deploy.PreCheck(false); err != nil {
		return err
	}

	version, err := GetVersion()
	if err != nil {
		return err
	}

	log.Infof("Publishing panther-community v%s to %s", version, strings.Join(publishRegions, ","))
	result := prompt.Read("Are you sure you want to continue? (yes|no) ", prompt.NonemptyValidator)
	if strings.ToLower(result) != "yes" {
		return fmt.Errorf("publish aborted")
	}

	// To be safe, always clean and reset the repo before building the assets
	if err := clean.Clean(); err != nil {
		return err
	}
	if err := setup.Setup(); err != nil {
		return err
	}
	if err := Build(log); err != nil {
		return err
	}

	for _, region := range publishRegions {
		if err := publishToRegion(log, version, region); err != nil {
			return err
		}
	}

	return nil
}

func publishToRegion(log *zap.SugaredLogger, version, region string) error {
	log.Infof("publishing to %s", region)
	// Override the region for the AWS session and clients.
	clients.SetRegion(region)

	bucket := util.PublicAssetsBucket()
	s3Key := fmt.Sprintf("v%s/panther.yml", version)
	s3URL := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucket, s3Key)

	// Check if this version already exists - it's easy to forget to update the version
	// in the template file and we don't want to overwrite a previous version.
	_, err := clients.S3().HeadObject(&s3.HeadObjectInput{Bucket: &bucket, Key: &s3Key})
	if err == nil {
		return fmt.Errorf("%s already exists", s3URL)
	}
	if !awsutils.IsAnyError(err, "NotFound") {
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
