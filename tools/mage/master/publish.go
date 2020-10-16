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
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/setup"
	"github.com/panther-labs/panther/tools/mage/srcfmt"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Publish a new Panther release (Panther team only)
func Publish() error {
	log := logger.Build("[master:publish]")
	if err := deploy.PreCheck(); err != nil {
		return err
	}

	version := util.RepoVersion()
	if strings.HasSuffix(version, "-dirty") {
		return fmt.Errorf("you have local changes; commit or stash them before publishing")
	}
	if !strings.Contains(version, "-release-1.") {
		return fmt.Errorf("publication is only allowed from a release-1.X branch")
	}

	if err := getPublicationApproval(log, version); err != nil {
		return err
	}

	// To be safe, always reset dependencies, clear build artifacts, and re-generate source files before publishing.
	// Don't need to do a full 'mage clean', but we do want to remove the `out/` directory
	log.Info("rm -r out/")
	if err := os.RemoveAll("out"); err != nil {
		return fmt.Errorf("failed to remove out/ : %v", err)
	}
	if err := setup.Setup(); err != nil {
		return err
	}
	if err := Build(log); err != nil {
		return err
	}
	if err := srcfmt.Fmt(); err != nil { // to avoid dirty repo state after `mage gen` in the previous step
		return err
	}

	for _, region := range publishRegions {
		if err := publishToRegion(log, version, region); err != nil {
			return err
		}
	}

	return nil
}

func getPublicationApproval(log *zap.SugaredLogger, version string) error {
	log.Infof("Publishing panther-community %s to %s", version, strings.Join(publishRegions, ","))
	result := prompt.Read("Are you sure you want to continue? (yes|no) ", prompt.NonemptyValidator)
	if strings.ToLower(result) != "yes" {
		return fmt.Errorf("publish %s aborted by user", version)
	}

	// Check if the version already exists in any region - it's easy to forget to update the version
	// in the template file and we probably don't want to overwrite a previous version.
	for _, region := range publishRegions {
		// Override the region for the AWS session and clients.
		clients.SetRegion(region)
		bucket, s3Key, s3URL := s3MasterTemplate(version)

		_, err := clients.S3().HeadObject(&s3.HeadObjectInput{Bucket: &bucket, Key: &s3Key})
		if err == nil {
			log.Warnf("%s already exists", s3URL)
			result := prompt.Read("Are you sure you want to overwrite the published release in each region? (yes|no) ",
				prompt.NonemptyValidator)
			if strings.ToLower(result) != "yes" {
				return fmt.Errorf("publish %s aborted by user", version)
			}
			return nil // override approved - don't need to keep checking each region
		}

		if !awsutils.IsAnyError(err, "NotFound") {
			// Some error other than 'not found'
			return fmt.Errorf("failed to describe %s : %v", s3URL, err)
		}
	}

	return nil
}

func publishToRegion(log *zap.SugaredLogger, version, region string) error {
	log.Infof("publishing to %s", region)
	// Override the region for the AWS session and clients.
	clients.SetRegion(region)
	bucket, s3Key, s3URL := s3MasterTemplate(version)

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

// Returns bucket name, s3 object key, and S3 URL for the master template in the current region.
func s3MasterTemplate(version string) (string, string, string) {
	bucket := util.PublicAssetsBucket()
	s3Key := strings.SplitN(version, "-", 2)[0] + "/panther.yml"
	s3URL := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucket, s3Key)
	return bucket, s3Key, s3URL
}
