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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/cfnparse"
	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/config"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/util"
)

const (
	// The region will be interpolated in these names
	publicImageRepository = "349240696275.dkr.ecr.%s.amazonaws.com/panther-community"
	masterStackName       = "panther"
)

var (
	publishRegions = []string{"us-east-1", "us-east-2", "us-west-2"}
)

type Master mg.Namespace

// Deploy Deploy single master template (deployments/master.yml) nesting all other stacks
func (Master) Deploy() {
	bucket, firstUserEmail, ecrRegistry := masterDeployPreCheck()

	masterBuild()
	pkg := masterPackage(clients.Region(), bucket, getMasterVersion(), ecrRegistry)

	err := sh.RunV(filepath.Join(pythonVirtualEnvPath, "bin", "sam"), "deploy",
		"--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND",
		"--region", clients.Region(),
		"--stack-name", masterStackName,
		"-t", pkg,
		"--parameter-overrides", "FirstUserEmail="+firstUserEmail, "ImageRegistry="+ecrRegistry)
	if err != nil {
		log.Fatal(err)
	}
}

// Ensure environment is configured correctly for the master template.
//
// Returns bucket, firstUserEmail, ecrRegistry
func masterDeployPreCheck() (string, string, string) {
	deployPreCheck(false)

	_, err := clients.Cfn().DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String(cfnstacks.Bootstrap)})
	if err == nil {
		// Multiple Panther deployments won't work in the same region in the same account.
		// Named resources (e.g. IAM roles) will conflict
		log.Fatalf("%s stack already exists, can't deploy master template", cfnstacks.Bootstrap)
	}

	bucket := os.Getenv("BUCKET")
	firstUserEmail := os.Getenv("EMAIL")
	ecrRegistry := os.Getenv("ECR_REGISTRY")
	if bucket == "" || firstUserEmail == "" || ecrRegistry == "" {
		log.Error("BUCKET, EMAIL, and ECR_REGISTRY env variables must be defined")
		log.Info("    BUCKET - S3 bucket for staging assets in the deployment region")
		log.Info("    EMAIL - email for inviting the first Panther admin user")
		log.Info("    ECR_REGISTRY - where to push docker images, e.g. " +
			"111122223333.dkr.ecr.us-west-2.amazonaws.com/panther-web")
		log.Fatal("invalid environment")
	}

	return bucket, firstUserEmail, ecrRegistry
}

// Publish Publish a new Panther release (Panther team only)
func (Master) Publish() {
	deployPreCheck(false)
	version := getMasterVersion()

	log.Infof("Publishing panther-community v%s to %s", version, strings.Join(publishRegions, ","))
	result := prompt.Read("Are you sure you want to continue? (yes|no) ", prompt.NonemptyValidator)
	if strings.ToLower(result) != "yes" {
		log.Fatal("publish aborted")
	}

	// To be safe, always clean and reset the repo before building the assets
	Clean()
	Setup()
	masterBuild()

	for _, region := range publishRegions {
		publishToRegion(version, region)
	}
}

// Compile Lambda source assets
func masterBuild() {
	build.API()
	build.Cfn()
	build.Lambda()

	// Use the pip libraries in the default settings file when building the layer.
	defaultConfig, err := config.Settings()
	if err != nil {
		log.Fatal(err)
	}

	if err = buildLayer(defaultConfig.Infra.PipLayer); err != nil {
		log.Fatal(err)
	}
}

// Package assets needed for the master template.
//
// Returns the path to the final generated template.
func masterPackage(region, bucket, pantherVersion, imgRegistry string) string {
	pkg, err := samPackage(region, "deployments/master.yml", bucket)
	if err != nil {
		log.Fatal(err)
	}

	dockerImage, err := buildAndPushImageFromSource(imgRegistry, pantherVersion)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("successfully published docker image %s", dockerImage)
	return pkg
}

// Get the Panther version indicated in the master template.
func getMasterVersion() string {
	type template struct {
		Mappings struct {
			Constants struct {
				Panther struct {
					Version string
				}
			}
		}
	}

	var cfn template
	if err := cfnparse.ParseTemplate(pythonVirtualEnvPath, "deployments/master.yml", &cfn); err != nil {
		log.Fatal(err)
	}

	if cfn.Mappings.Constants.Panther.Version == "" {
		log.Fatal("Mappings:Constants:Panther:Version not found in deployments/master.yml")
	}

	return cfn.Mappings.Constants.Panther.Version
}

func publishToRegion(version, region string) {
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
		log.Errorf("%s already exists", s3URL)
		return
	}
	if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != "NotFound" {
		// Some error other than 'not found'
		log.Fatalf("failed to describe %s : %v", s3URL, err)
	}

	// Publish S3 assets and ECR docker image
	pkg := masterPackage(region, bucket, version, fmt.Sprintf(publicImageRepository, region))

	// Upload final packaged template
	if _, err := util.UploadFileToS3(pkg, bucket, s3Key); err != nil {
		log.Fatalf("failed to upload %s : %v", s3URL, err)
	}

	log.Infof("successfully published %s", s3URL)
}
