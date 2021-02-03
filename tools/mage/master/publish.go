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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/pkg"
	"github.com/panther-labs/panther/tools/mage/util"
)

const (
	// AWS Account where Panther publishes release assets
	publicAccountID = "349240696275"

	publicEcrRepoName = "panther-community"
)

// Publish a new Panther release (Panther team only)
func Publish() error {
	log := logger.Build("[master:publish]")
	if err := deploy.PreCheck(""); err != nil {
		return err
	}

	// Don't allow publishing with a dirty repo state
	if err := sh.Run("git", "diff", "--quiet"); err != nil {
		if strings.HasSuffix(err.Error(), "failed with exit code 1") {
			return fmt.Errorf("you have local changes; commit or stash them before publishing")
		}
		return fmt.Errorf("git diff failed: %s", err)
	}

	// Only allow publishing from the release branch
	// "git branch --show-current" works only for Git 2.22+, but this is compatible with older versions:
	branch, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return fmt.Errorf("failed to get name of current branch: %s", err)
	}
	if !strings.HasPrefix(branch, "release-") {
		return fmt.Errorf("publication is only allowed from a release-* branch")
	}

	var regions []string
	if env := os.Getenv("REGION"); env == "" {
		for region := range deploy.SupportedRegions {
			regions = append(regions, region)
		}
	} else {
		regions = strings.Split(env, ",")
	}

	if err := getPublicationApproval(log, regions); err != nil {
		return err
	}

	// To be safe, always clear build artifacts before publishing.
	// Don't need to do a full 'mage clean', but we do want to remove the `out/` directory
	log.Info("rm -r out/")
	if err := os.RemoveAll("out"); err != nil {
		return fmt.Errorf("failed to remove out/ : %v", err)
	}

	// 'mage setup' not required to publish - npm and python aren't needed

	imgID, err := pkg.DockerBuild(log, filepath.Join("deployments", "Dockerfile"))
	if err != nil {
		return err
	}

	// Publish to each region.
	for _, region := range regions {
		if !deploy.SupportedRegions[region] {
			return fmt.Errorf("%s is not a supported region", region)
		}

		if err := publishToRegion(log, region, imgID); err != nil {
			return err
		}
	}

	return nil
}

func getPublicationApproval(log *zap.SugaredLogger, regions []string) error {
	log.Infof("Publishing panther-community %s to %s", util.Semver(), strings.Join(regions, ", "))
	result := prompt.Read("Are you sure you want to continue? (yes|no) ", prompt.NonemptyValidator)
	if strings.ToLower(result) != "yes" {
		return fmt.Errorf("publish %s aborted by user", util.Semver())
	}

	// Check if the version already exists in any region - it's easy to forget to update the version
	// in the template file and we probably don't want to overwrite a previous version.
	for _, region := range regions {
		bucket, s3Key, s3URL := s3MasterTemplate(region)

		awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
		if err != nil {
			return err
		}

		_, err = s3.NewFromConfig(awsCfg).HeadObject(context.TODO(), &s3.HeadObjectInput{Bucket: &bucket, Key: &s3Key})
		if err == nil {
			log.Warnf("%s already exists", s3URL)
			result := prompt.Read("Are you sure you want to overwrite the published release in each region? (yes|no) ",
				prompt.NonemptyValidator)
			if strings.ToLower(result) != "yes" {
				return fmt.Errorf("publish %s aborted by user", util.Semver())
			}
			return nil // override approved - don't need to keep checking each region
		}

		var notFound *s3Types.NotFound
		if !errors.As(err, &notFound) {
			// Some error other than 'not found'
			return fmt.Errorf("failed to describe %s : %v", s3URL, err)
		}
	}

	return nil
}

func publishToRegion(log *zap.SugaredLogger, region, imgID string) error {
	log.Infof("publishing to %s", region)

	// We need a different session for each region.
	awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("failed to build AWS config: %v", err)
	}

	bucket, s3Key, s3URL := s3MasterTemplate(region)

	packager := pkg.Packager{
		Log:            log,
		AwsConfig:      awsCfg,
		Bucket:         bucket,
		DockerImageID:  imgID,
		EcrRegistry:    util.EcrRepoURI(publicAccountID, region, publicEcrRepoName),
		EcrTagWithHash: false,
		PipLibs:        defaultPipLayer,
		PostProcess:    embedVersion,
	}
	pkgTemplate, err := packager.Template(rootTemplate)
	if err != nil {
		return err
	}

	if _, _, err = packager.UploadAsset(pkgTemplate, s3Key); err != nil {
		return err
	}

	log.Infof("successfully published %s", s3URL)
	return nil
}

// Returns bucket name, s3 object key, and S3 URL for the master template in the current region.
func s3MasterTemplate(region string) (string, string, string) {
	bucket := util.PublicAssetsBucket(region)
	s3Key := fmt.Sprintf("v%s/panther.yml", util.Semver())
	return bucket, s3Key, util.S3ObjectURL(region, bucket, s3Key)
}
