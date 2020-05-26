package mage

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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/config"
)

// https://docs.aws.amazon.com/serverlessrepo/latest/devguide/serverlessrepo-how-to-publish.html
const sarReadPolicy = `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "serverlessrepo.amazonaws.com"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::%s/*"
        }
    ]
}
`

// Release Publish nested SAR apps
func Release() {
	version := os.Getenv("SEMVER")
	if version == "" {
		logger.Fatal("please set SEMVER env variable with the version you want to publish")
	}

	awsSession, err := session.NewSession(&aws.Config{Region: aws.String("us-east-1")})
	if err != nil {
		logger.Fatal(err)
	}

	bucket, err := sarStagingBucket(awsSession)
	if err != nil {
		logger.Fatal(err)
	}

	if err := buildSarAssets(); err != nil {
		logger.Fatal(err)
	}

	logger.Infof("release: using S3 bucket %s for temporary SAR packaging", bucket)

	templates := []string{
		bootstrapTemplate, gatewayTemplate, appsyncTemplate, coreTemplate,
		cloudsecTemplate, dashboardTemplate, logAnalysisTemplate,
	}
	for _, t := range templates {
		if err = sarPublish(t, *awsSession.Config.Region, bucket, version); err != nil {
			logger.Fatal(err)
		}
	}
}

// Do a fresh build of all assets to prepare for SAR packaging.
//
// This is essentially the same build process that happens during a normal deploy.
func buildSarAssets() error {
	if err := os.RemoveAll("out"); err != nil {
		logger.Warnf("failed to remove out directory: %v", err)
	}

	if err := build.api(); err != nil {
		return err
	}
	if err := build.cfn(); err != nil {
		return err
	}
	if err := build.lambda(); err != nil {
		return err
	}

	settings, err := config.Settings()
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", config.Filepath, err)
	}
	return buildLayer(settings.Infra.PipLayer)
}

// Get the name of the bucket for staging SAR packaging and set its policy.
//
// After the SAR app is created, these assets can be safely discarded.
func sarStagingBucket(awsSession *session.Session) (string, error) {
	bucket := os.Getenv("BUCKET")
	if bucket == "" {
		return "", errors.New("define BUCKET env variable " +
			"(S3 bucket in us-east-1 for temporarily staging SAR assets)")
	}

	_, err := s3.New(awsSession).PutBucketPolicy(&s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: aws.String(fmt.Sprintf(sarReadPolicy, bucket)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to put bucket policy: %v", err)
	}

	return bucket, nil
}

// Package and publish a SAR application.
//
// TODO - global SAR app / publish in every supported region
func sarPublish(templatePath, region, bucket, version string) error {
	logger.Infof("release: publishing %s version %s", templatePath, version)

	// Note: combined size of SAR S3 artifacts cannot exceed 52428800 bytes
	pkg, err := samPackage(region, templatePath, bucket)
	if err != nil {
		return err
	}

	return sh.Run(filepath.Join(pythonVirtualEnvPath, "bin", "sam"),
		"publish", "-t", pkg, "--region", region, "--semantic-version", version)
}
