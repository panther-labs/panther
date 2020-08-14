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
	"net/http"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/magefile/mage/sh"

	analysisclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	analysisops "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/prompt"
)

const (
	systemUserID = "00000000-0000-4000-8000-000000000000"
	outputsAPI   = "panther-outputs-api"
)

// Maintain context about the test as it progresses
type e2eContext struct {
	// Added in stage 1
	FirstUserEmail string
	GatewayClient  *http.Client
	Region         string

	// Added in stage 2
	AnalysisClient      *analysisclient.PantherAnalysis // analysis-api
	GatewayStackOutputs map[string]string

	// Added in stage 3
	OutputQueue outputmodels.AlertOutput
	NewPolicy   analysismodels.Policy
	NewRule     analysismodels.Rule
}

// End-to-end test suite - deploy, migrate, test, teardown
func (Test) E2e() {
	ctx := e2eContext{
		FirstUserEmail: prompt.Read("Email for initial invite: ", prompt.EmailValidator),
	}

	// TODO - allow specifying STAGE to jump to

	// Make sure there are no leftover resources that would fail the deployment.
	logger.Info("***** test:e2e : Stage 1/10 : Pre-Teardown *****")
	Teardown() // includes getSession()
	// I tried removing AWSService IAM roles here - AWS does not allow it

	ctx.GatewayClient = gatewayapi.GatewayClient(awsSession)
	ctx.Region = *awsSession.Config.Region
	ctx.deployPreviousVersion()
	ctx.interactWithOldVersion()

	// TODO - stage 4 - migration - current master template (with deployment role)
	// TODO - stage 5 - verify migrated data - verify app functionality
	// TODO - stage 6 - integration test
	// TODO - stage 7 - teardown + verify no leftover resources
}

// Deploy the official published pre-packaged deployment for the previous version.
func (ctx *e2eContext) deployPreviousVersion() {
	logger.Info("***** test:e2e : Stage 2/10 : Deploy Previous Release *****")
	getGitVersion(false)
	s3URL := fmt.Sprintf("https://panther-community-%s.s3.amazonaws.com/%s/panther.yml",
		ctx.Region, strings.Split(gitVersion, "-")[0])
	downloadPath := filepath.Join("out", "deployments", "panther.yml")
	logger.Infof("downloading %s to %s", s3URL, downloadPath)
	if err := runWithCapturedOutput("curl", s3URL, "--output", downloadPath); err != nil {
		logger.Fatal(err)
	}

	// Deploy the template directly, do not use our standard deploy code with packaging.
	err := sh.RunV(filepath.Join(pythonVirtualEnvPath, "bin", "sam"), "deploy",
		"--capabilities", "CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM",
		"--parameter-overrides", "CompanyDisplayName=e2e-test", "FirstUserEmail="+ctx.FirstUserEmail,
		"--region", ctx.Region,
		"--stack-name", "panther",
		"--template", downloadPath,
	)
	if err != nil {
		logger.Fatal(err)
	}

	// Lookup API gateway IDs
	// These aren't top-level outputs, so we need to find the gateway nested stack.
	cfnClient := cfn.New(awsSession)
	var gatewayStackName string
	listStacksInput := &cfn.ListStacksInput{
		StackStatusFilter: []*string{
			aws.String(cfn.StackStatusCreateComplete),
			aws.String(cfn.StackStatusUpdateComplete),
			aws.String(cfn.StackStatusUpdateRollbackComplete),
		},
	}
	err = cfnClient.ListStacksPages(listStacksInput, func(page *cfn.ListStacksOutput, isLast bool) bool {
		for _, stack := range page.StackSummaries {
			if strings.HasPrefix(*stack.StackName, "panther-BootstrapGateway") {
				gatewayStackName = *stack.StackName
				return false // stop paging
			}
		}
		return true // keep paging
	})
	if err != nil {
		logger.Fatalf("failed to list CloudFormation stacks: %v", err)
	}
	if gatewayStackName == "" {
		logger.Fatal("failed to find successful panther-BootstrapGateway stack")
	}

	outputs := awscfn.StackOutputs(cfnClient, logger, gatewayStackName)
	ctx.AnalysisClient = analysisclient.NewHTTPClientWithConfig(nil, analysisclient.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(outputs["AnalysisApiEndpoint"]))
}

// Interact with the last Panther release to generate some custom data we can verify after the migration.
func (ctx *e2eContext) interactWithOldVersion() {
	logger.Info("***** test:e2e : Stage 3/10 : Generate Data in Previous Release *****")

	// Add an SQS alert destination
	queue, err := sqs.New(awsSession).CreateQueue(&sqs.CreateQueueInput{
		QueueName: aws.String("e2e-test"),
	})
	if err != nil {
		logger.Fatalf("failed to create SQS queue: %v", err)
	}

	input := outputmodels.LambdaInput{
		AddOutput: &outputmodels.AddOutputInput{
			UserID:      aws.String(systemUserID),
			DisplayName: aws.String("e2e-test-queue"),
			OutputConfig: &outputmodels.OutputConfig{
				Sqs: &outputmodels.SqsConfig{QueueURL: *queue.QueueUrl},
			},
		},
	}
	if err := genericapi.Invoke(lambda.New(awsSession), outputsAPI, &input, &ctx.OutputQueue); err != nil {
		logger.Fatalf("failed to add SQS output in %s: %v", outputsAPI, err)
	}
	logger.Infof("added SQS queue %s as output ID %s", *queue.QueueUrl, *ctx.OutputQueue.OutputID)

	// Add a policy which scans "panther-" stacks
	policy, err := ctx.AnalysisClient.Operations.CreatePolicy(&analysisops.CreatePolicyParams{
		Body: &analysismodels.UpdatePolicy{
			Body: `
def policy(resource):
    if not resource['Name'].startswith('panther-'):
        return True
    return resource['Tags'].get('Application') == 'Panther'
`,
			Description:   "E2E test - check tags in panther stacks",
			DisplayName:   "Tagged Panther Stacks",
			Enabled:       false,
			ID:            "E2E.TaggedPantherStacks",
			OutputIds:     []string{*ctx.OutputQueue.OutputID},
			ResourceTypes: []string{"AWS.CloudFormation.Stack"},
			Severity:      "INFO",
			UserID:        systemUserID,
		},
		HTTPClient: ctx.GatewayClient,
	})
	if err != nil {
		logger.Fatalf("failed to create policy from analysis-api: %v", err)
	}
	ctx.NewPolicy = *policy.Payload
	logger.Infof("added policy ID \"%s\"", ctx.NewPolicy.ID)

	// Add a rule which matches 10% of all input logs
	rule, err := ctx.AnalysisClient.Operations.CreateRule(&analysisops.CreateRuleParams{
		Body: &analysismodels.UpdateRule{
			Body: `
import random

def rule(event):
    return random.random() <= 0.10
`,
			DedupPeriodMinutes: 15,
			Description:        "E2E test - match 10% of all logs",
			DisplayName:        "Random Log Match",
			Enabled:            false,
			ID:                 "E2E.RandomLogMatch",
			Severity:           "INFO",
			UserID:             systemUserID,
		},
		HTTPClient: ctx.GatewayClient,
	})
	if err != nil {
		if badReq, ok := err.(*analysisops.CreateRuleBadRequest); ok {
			logger.Errorf("bad request: %s", *badReq.Payload.Message)
		}
		logger.Fatalf("failed to create rule from analysis-api: %v", err)
	}
	ctx.NewRule = *rule.Payload
	logger.Infof("added rule ID \"%s\"", ctx.NewRule.ID)
}
