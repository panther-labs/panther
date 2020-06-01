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
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/cfnparse"
	"github.com/panther-labs/panther/tools/config"
)

// Deploy master template (deployments/master.yml)
func Master() {
	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}
	region := *awsSession.Config.Region
	bucket, firstUserEmail, ecrRegistry := masterPreCheck(awsSession)

	masterBuild(awsSession, ecrRegistry)

	pkg, err := samPackage(region, "deployments/master.yml", bucket)
	if err != nil {
		logger.Fatal(err)
	}

	err = sh.RunV(filepath.Join(pythonVirtualEnvPath, "bin", "sam"), "deploy",
		"--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND",
		"--region", region,
		"--stack-name", "panther-master",
		"-t", pkg,
		"--parameter-overrides", "FirstUserEmail="+firstUserEmail, "ImageRegistry="+ecrRegistry)
	if err != nil {
		logger.Fatal(err)
	}
}

// Ensure environment is configured correctly for the master template.
//
// Returns bucket, firstUserEmail, ecrRegistry
func masterPreCheck(awsSession *session.Session) (string, string, string) {
	deployPreCheck(*awsSession.Config.Region)

	_, err := cloudformation.New(awsSession).DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String(bootstrapStack)})
	if err == nil {
		// Multiple Panther deployments won't work in the same region in the same account.
		// Named resources (e.g. IAM roles) will conflict
		logger.Fatalf("%s stack already exists, can't deploy master template", bootstrapStack)
	}

	bucket := os.Getenv("BUCKET")
	firstUserEmail := os.Getenv("EMAIL")
	ecrRegistry := os.Getenv("ECR_REGISTRY")
	if bucket == "" || firstUserEmail == "" || ecrRegistry == "" {
		logger.Error("BUCKET, EMAIL, and ECR_REGISTRY env variables must be defined")
		logger.Info("    BUCKET - S3 bucket for staging assets in the deployment region")
		logger.Info("    EMAIL - email for inviting the first Panther admin user")
		logger.Info("    ECR_REGISTRY - where to push docker images, e.g. " +
			"111122223333.dkr.ecr.us-west-2.amazonaws.com/panther-web")
		logger.Fatal("invalid environment")
	}

	return bucket, firstUserEmail, ecrRegistry
}

// Build assets needed for the master template.
func masterBuild(awsSession *session.Session, imgRegistry string) {
	build.API()
	build.Cfn()
	build.Lambda()

	// Use the pip libraries in the default settings file when building the layer.
	defaultConfig, err := config.Settings()
	if err != nil {
		logger.Fatal(err)
	}

	if err = buildLayer(defaultConfig.Infra.PipLayer); err != nil {
		logger.Fatal(err)
	}

	// Use the version from the master template for the docker image tag
	cfn, err := cfnparse.ParseTemplate("deployments/master.yml")
	if err != nil {
		logger.Fatal(err)
	}
	type m = map[string]interface{}
	version := cfn["Mappings"].(m)["Constants"].(m)["Panther"].(m)["Version"].(string)

	dockerImage, err := buildAndPushImageFromSource(awsSession, imgRegistry, version)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Infof("successfully published docker image %s", dockerImage)
}
