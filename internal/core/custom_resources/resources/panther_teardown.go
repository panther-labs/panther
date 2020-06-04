package resources

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

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/lambda"
	"go.uber.org/zap"
)

const globalLayerName = "panther-engine-globals"

type PantherTeardownProperties struct {
	EcrRepoName string
}

func customPantherTeardown(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const resourceID = "custom:panther-teardown:singleton"

	switch event.RequestType {
	case cfn.RequestDelete:
		var props PantherTeardownProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return resourceID, nil, err
		}

		if props.EcrRepoName != "" {
			if err := destroyEcrRepo(props.EcrRepoName); err != nil {
				return resourceID, nil, err
			}
		}

		return resourceID, nil, destroyLambdaLayers()

	default:
		// skip creates/updates
		return resourceID, nil, nil
	}
}

// ECR repos can't be deleted by CloudFormation unless they are empty.
func destroyEcrRepo(repoName string) error {
	zap.L().Info("removing ECR repository", zap.String("repo", repoName))
	_, err := ecrClient.DeleteRepository(&ecr.DeleteRepositoryInput{
		// Force:true to remove images as well (easier than emptying the repo explicitly)
		Force:          aws.Bool(true),
		RepositoryName: &repoName,
	})

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == ecr.ErrCodeRepositoryNotFoundException {
		// repo doesn't exist - that's fine, nothing to do here
		err = nil
	}
	return err
}

// Remove layers created for the policy and rules engines
func destroyLambdaLayers() error {
	versions, err := lambdaClient.ListLayerVersions(
		&lambda.ListLayerVersionsInput{LayerName: aws.String(globalLayerName)})
	if err != nil {
		return fmt.Errorf("failed to remove layer %s: %v", globalLayerName, err)
	}

	for _, version := range versions.LayerVersions {
		_, err := lambdaClient.DeleteLayerVersion(&lambda.DeleteLayerVersionInput{
			LayerName:     aws.String(globalLayerName),
			VersionNumber: version.Version,
		})
		if err != nil {
			return fmt.Errorf("failed to delete layer version %d: %v", aws.Int64Value(version.Version), err)
		}
	}

	return nil
}
