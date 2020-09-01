// Package e2e provides an end-to-end deployment test, triggered by 'mage test:e2e'
package e2e

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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/magefile/mage/sh"
	"github.com/stretchr/testify/require"

	analysisclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

const (
	numStages    = 8
	pollInterval = 5 * time.Minute

	masterStackName = "panther"
	companyName     = "panther-e2e-test"
	userFirstName   = "E2E"
	userLastName    = "Test"
)

// We want timestamps, colors, and levels, so we use the standard mage logger
// instead of t.Log() from the testing library.
var log = logger.Get()

// The working directory at runtime will be the directory containing this file: tools/mage/e2e
var repoRoot = filepath.Join("..", "..", "..")

// Using the testing library (instead of adding to mage directly) makes it easier to add assertions.
// This also avoids bloating mage with all of the compiled testing code.
//
// It's recommended to run this test in a fresh account when possible.
//
// 'mage test:e2e' will set the following environment variables based on user input:
//     EMAIL: (first user email)
//     INTEGRATION_TEST: True (to enable the test)
//     OLD_VERSION: (published panther version we will migrate from, e.g. "1.7.1")
//     STAGE: (testing stage to start at)
func TestIntegrationEndToEnd(t *testing.T) {
	if strings.ToLower(os.Getenv("INTEGRATION_TEST")) != "true" {
		t.Skip()
	}

	startStage, err := strconv.Atoi(os.Getenv("STAGE"))
	require.NoError(t, err)

	if startStage == 1 {
		t.Run("PreTeardown", preTeardown)
	}
	if startStage <= 2 {
		t.Run("DeployPreviousVersion", deployPreviousVersion)
	}
}

// Teardown all Panther resources in the region to start with a clean slate.
func preTeardown(t *testing.T) {
	// NOTE: AWS does not allow programmatically removing AWSService IAM roles
	log.Infof("***** test:e2e : Stage 1/%d : Pre-Teardown *****", numStages)

	// Same as 'mage teardown', except clearing both source and master deployments
	require.NoError(t, util.DestroyCfnStacks("", pollInterval))
	require.NoError(t, util.DestroyCfnStacks(masterStackName, pollInterval))
	require.NoError(t, util.DestroyPantherBuckets(clients.S3()))
}

// Deploy the official published pre-packaged deployment for the previous version.
func deployPreviousVersion(t *testing.T) {
	log.Infof("***** test:e2e : Stage 2/%d : Deploy Previous Release *****", numStages)

	// Download previous published release
	s3URL := fmt.Sprintf("https://panther-community-%s.s3.amazonaws.com/v%s/panther.yml",
		clients.Region(), os.Getenv("OLD_VERSION"))
	downloadPath, err := filepath.Abs(filepath.Join(repoRoot, "out", "deployments", "panther.yml"))
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(downloadPath), 0700))

	log.Infof("downloading %s to %s", s3URL, downloadPath)
	require.NoError(t, util.RunWithCapturedOutput("curl", s3URL, "--output", downloadPath))

	// Deploy the template directly, do not use 'mage deploy' code because everything is already packaged.
	require.NoError(t, sh.RunV(
		filepath.Join(repoRoot, util.PythonLibPath("sam")),
		"deploy",
		"--capabilities", "CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM",
		"--parameter-overrides", "CompanyDisplayName="+companyName, "FirstUserEmail="+os.Getenv("EMAIL"),
		"FirstUserGivenName="+userFirstName, "FirstUserFamilyName="+userLastName,
		"--region", clients.Region(),
		"--stack-name", masterStackName,
		"--template", downloadPath,
	))

	// Lookup API gateway IDs
	// These aren't top-level outputs, so we need to find the gateway nested stack.
	cfnClient := clients.Cfn()
	var gatewayStackName string
	listStacksInput := &cfn.ListStacksInput{
		StackStatusFilter: []*string{
			aws.String(cfn.StackStatusCreateComplete),
			aws.String(cfn.StackStatusUpdateComplete),
			aws.String(cfn.StackStatusUpdateRollbackComplete),
		},
	}
	require.NoError(t, cfnClient.ListStacksPages(listStacksInput, func(page *cfn.ListStacksOutput, isLast bool) bool {
		for _, stack := range page.StackSummaries {
			if strings.HasPrefix(*stack.StackName, "panther-BootstrapGateway") {
				gatewayStackName = *stack.StackName
				return false // stop paging
			}
		}
		return true // keep paging
	}))
	require.NotEmpty(t, gatewayStackName, "failed to find successful panther-BootstrapGateway stack")

	outputs := awscfn.StackOutputs(cfnClient, log, gatewayStackName)
	log.Infof("found outputs: %v", outputs)
	analysisClient := analysisclient.NewHTTPClientWithConfig(nil, analysisclient.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(outputs["AnalysisApiEndpoint"]))
	require.NotNil(t, analysisClient)
}
