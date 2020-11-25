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
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

const defaultStackName = "panther"

// Path to master stack with embedded version information
var embedPath = filepath.Join("out", "deployments", "embedded.master.yml")

// Deploy single master template nesting all other stacks.
//
// This allows developers to simulate the customer deployment flow and test the master
// template before publishing a release.
func Deploy() error {
	log := logger.Build("[master:deploy]")
	if err := masterDeployPreCheck(); err != nil {
		return err
	}

	var stack string
	if stack = os.Getenv("STACK"); stack == "" {
		stack = defaultStackName
	}

	version := util.RepoVersion()
	log.Infof("deploying %s %s to %s (%s) as stack '%s'", masterTemplate, version, clients.AccountID(), clients.Region(), stack)
	email := prompt.Read("First user email: ", prompt.EmailValidator)

	dockerImageID, err := buildAssets(log, version)
	if err != nil {
		return err
	}

	// Create S3 bucket for staging assets
	bucket := fmt.Sprintf("panther-dev-%s-master-%s", clients.AccountID(), clients.Region())
	if _, err := clients.S3().CreateBucket(&s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() != s3.ErrCodeBucketAlreadyOwnedByYou &&
			awsErr.Code() != s3.ErrCodeBucketAlreadyExists {

			return fmt.Errorf("failed to create S3 bucket %s: %v", bucket, err)
		}
	}

	// Delete packaged assets after a few days
	if _, err := clients.S3().PutBucketLifecycleConfiguration(&s3.PutBucketLifecycleConfigurationInput{
		Bucket: &bucket,
		LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
			Rules: []*s3.LifecycleRule{
				{
					AbortIncompleteMultipartUpload: &s3.AbortIncompleteMultipartUpload{
						DaysAfterInitiation: aws.Int64(1),
					},
					Expiration: &s3.LifecycleExpiration{
						Days: aws.Int64(7),
					},
					Filter: &s3.LifecycleRuleFilter{
						Prefix: aws.String(""),
					},
					ID:     aws.String("expire-everything"),
					Status: aws.String("Enabled"),
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to put S3 bucket lifecycle policy: %v", err)
	}

	// Create ECR repo
	const repoName = "panther-dev-master"
	if _, err := clients.ECR().CreateRepository(&ecr.CreateRepositoryInput{
		RepositoryName: aws.String(repoName),
	}); err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() != ecr.ErrCodeRepositoryAlreadyExistsException {
			return fmt.Errorf("failed to create ECR repo %s: %v", repoName, err)
		}
	}
	var registryURI = fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", clients.AccountID(), clients.Region(), repoName)

	pkg, err := pkgAssets(log, clients.Region(), bucket, version, registryURI, dockerImageID)
	if err != nil {
		return err
	}

	return util.SamDeploy(defaultStackName, pkg, "FirstUserEmail="+email, "ImageRegistry="+registryURI)
}

// Stop early if there is a known issue with the dev environment.
func masterDeployPreCheck() error {
	if err := deploy.PreCheck(); err != nil {
		return err
	}

	_, err := clients.Cfn().DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String(cfnstacks.Bootstrap)})
	if err == nil {
		// Multiple Panther deployments won't work in the same region in the same account.
		// Named resources (e.g. IAM roles) will conflict
		return fmt.Errorf("%s stack already exists, can't deploy master template", cfnstacks.Bootstrap)
	}

	return nil
}
