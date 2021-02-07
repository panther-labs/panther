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
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"

	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/pkg"
	"github.com/panther-labs/panther/tools/mage/util"
)

const devStackName = "panther-dev"

var (
	devTemplate  = filepath.Join("deployments", "dev.yml")
	rootTemplate = filepath.Join("deployments", "root.yml")
)

// Deploy the root template nesting all other stacks.
func Deploy() error {
	start := time.Now()
	log := logger.Build("[master:deploy]")

	awsCfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}

	if err := deployPreCheck(awsCfg); err != nil {
		return err
	}

	// Prompt for email if needed
	devCfg, err := buildRootConfig(log)
	if err != nil {
		return err
	}

	// Deploy panther-dev stack to initialize S3 bucket and ECR repo
	devOutputs, err := deploy.Stack(nil, devTemplate, devStackName, nil)
	if err != nil {
		return err
	}

	// Docker build before the parallel packaging.
	// It's too resource-intensive to run in parallel with other build operations.
	imgID, err := pkg.DockerBuild(log, filepath.Join("deployments", "Dockerfile"))
	if err != nil {
		return err
	}

	packager := &pkg.Packager{
		Log:            log,
		AwsConfig:      awsCfg,
		Bucket:         devOutputs["SourceBucket"],
		DockerImageID:  imgID,
		EcrRegistry:    devOutputs["ImageRegistryUri"],
		EcrTagWithHash: true,
		PipLibs:        devCfg.PipLayer,
		PostProcess:    embedVersion,
	}

	// TODO - cfn waiters need better progress updates and error extraction for nested stacks
	// TODO - support updating nested stacks directly
	// TODO - use deployment IAM role
	// TODO - expose 'mage pkg' target
	log.Infof("deploying %s %s (%s) to account %s (%s) as stack '%s'", rootTemplate,
		util.Semver(), util.CommitSha(), util.AccountID(awsCfg), awsCfg.Region, devCfg.RootStackName)
	log.Debugf("parameter overrides: %s", devCfg.ParameterOverrides)
	rootOutputs, err := deploy.Stack(packager, rootTemplate, devCfg.RootStackName, devCfg.ParameterOverrides)
	if err != nil {
		return err
	}

	log.Infof("finished in %s: Panther URL = %s",
		time.Since(start).Round(time.Second), rootOutputs["LoadBalancerUrl"])
	return nil
}

// Stop early if there is a known issue with the dev environment.
func deployPreCheck(config aws.Config) error {
	if err := deploy.PreCheck(config.Region); err != nil {
		return err
	}

	_, err := cloudformation.NewFromConfig(config).DescribeStacks(context.TODO(),
		&cloudformation.DescribeStacksInput{StackName: aws.String(cfnstacks.Bootstrap)})
	if err == nil {
		// Multiple Panther deployments won't work in the same region in the same account.
		// Named resources (e.g. IAM roles) will conflict
		// TODO - the stack migration will happen here
		return fmt.Errorf("%s stack already exists, can't deploy root template", cfnstacks.Bootstrap)
	}

	return nil
}

// Embed version information into the packaged root stack.
//
// We don't want it to be a user-configurable parameter; it's a hardcoded mapping.
//
// There is roughly a 1.4% chance that the commit tag looks like scientific notation, e.g. "715623e8"
// Even if the value is surrounded by quotes in the original template, yaml.Marshal will remove them!
// Then CloudFormation will standardize the scientific notation, e.g. "7.15623E13"
//
// This is why we have to embed the version *after* the packaging and yaml marshal - so we can ensure
// it is surrounded by quotes and interpreted as a proper string
func embedVersion(originalPath string, packagedBody []byte) []byte {
	if originalPath != rootTemplate {
		return packagedBody // no changes to other templates
	}

	body := bytes.Replace(packagedBody, []byte("${{PANTHER_COMMIT}}"), []byte(`'`+util.CommitSha()+`'`), 1)
	return bytes.Replace(body, []byte("${{PANTHER_VERSION}}"), []byte(`'`+util.Semver()+`'`), 1)
}
