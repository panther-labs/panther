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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/clean"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/setup"
	"github.com/panther-labs/panther/tools/mage/util"
)

const (
	// The region will be interpolated in these names
	publicImageRepository = "349240696275.dkr.ecr.%s.amazonaws.com/panther-community"
	masterStackName       = "panther"
)

var publishRegions = []string{"us-east-1", "us-east-2", "us-west-2"}

// Deploy single master template (deployments/master.yml) nesting all other stacks
func Deploy() error {
	log := logger.Build("[master:deploy]")
	env, err := masterDeployPreCheck(log)
	if err != nil {
		return err
	}

	if err := Build(log); err != nil {
		return err
	}

	version, err := GetVersion()
	if err != nil {
		return err
	}

	pkg, err := Package(log, clients.Region(), env.bucketName, version, env.ecrRegistry)
	if err != nil {
		return err
	}

	return util.SamDeploy(masterStackName, pkg,
		"FirstUserEmail="+env.firstUserEmail, "ImageRegistry="+env.ecrRegistry)
}

type masterDeployParams struct {
	bucketName     string
	firstUserEmail string
	ecrRegistry    string
}

// Ensure environment is configured correctly for the master template.
//
// TODO - automatically create bucket and repo
//
// Returns bucket, firstUserEmail, ecrRegistry
func masterDeployPreCheck(log *zap.SugaredLogger) (*masterDeployParams, error) {
	if err := deploy.PreCheck(false); err != nil {
		return nil, err
	}

	_, err := clients.Cfn().DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String(cfnstacks.Bootstrap)})
	if err == nil {
		// Multiple Panther deployments won't work in the same region in the same account.
		// Named resources (e.g. IAM roles) will conflict
		return nil, fmt.Errorf("%s stack already exists, can't deploy master template", cfnstacks.Bootstrap)
	}

	params := masterDeployParams{
		bucketName:     os.Getenv("BUCKET"),
		firstUserEmail: os.Getenv("EMAIL"),
		ecrRegistry:    os.Getenv("ECR_REGISTRY"),
	}

	if params.bucketName == "" || params.firstUserEmail == "" || params.ecrRegistry == "" {
		log.Error("BUCKET, EMAIL, and ECR_REGISTRY env variables must be defined")
		log.Info("    BUCKET - S3 bucket for staging assets in the deployment region")
		log.Info("    EMAIL - email for inviting the first Panther admin user")
		log.Info("    ECR_REGISTRY - where to push docker images, e.g. " +
			"111122223333.dkr.ecr.us-west-2.amazonaws.com/panther-web")
		return nil, fmt.Errorf("invalid environment")
	}

	return &params, nil
}

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
