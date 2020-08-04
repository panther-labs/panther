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
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"

	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/tools/config"
)

// Return the list of Panther's CloudFormation files
func cfnFiles() []string {
	paths, err := filepath.Glob("deployments/*.yml")
	if err != nil {
		logger.Fatalf("failed to glob deployments: %v", err)
	}

	// Remove the config file
	var result []string
	for _, p := range paths {
		if p != config.Filepath {
			result = append(result, p)
		}
	}
	return result
}

// Returns the PantherVersion tag for the given stack.
//
// Will be blank if the stack or tag does not exist.
func stackVersion(stack string) (string, error) {
	response, err := cfn.New(awsSession).DescribeStacks(&cfn.DescribeStacksInput{StackName: &stack})
	if err != nil {
		if awscfn.ErrStackDoesNotExist(err) {
			return "", nil
		}
		return "", err
	}

	for _, tag := range response.Stacks[0].Tags {
		if aws.StringValue(tag.Key) == "PantherVersion" {
			return aws.StringValue(tag.Value), nil
		}
	}

	return "", nil
}
