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
	"github.com/aws/aws-sdk-go/aws/awserr"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/magefile/mage/sh"

	analysisclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	analysisops "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	orgmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	usermodels "github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/prompt"
)

const (
	systemUserID = "00000000-0000-4000-8000-000000000000"
	orgAPI       = "panther-organization-api"
	outputsAPI   = "panther-outputs-api"
	usersAPI     = "panther-users-api"

	e2eCompanyName  = "Panther Labs"
	e2eFirstName    = "Panther"
	e2eLastName     = "Tester"
	e2eResourceName = "panther-e2e-test" // TODO - rename ecrRepoName?

	e2ePolicyBody = `
def policy(resource):
    if not resource['Name'].startswith('panther-'):
        return True
    return resource['Tags'].get('Application') == 'Panther'
`
	e2ePolicyDescription = "E2E test - check tags in panther stacks"
	e2ePolicyID          = "E2E.TaggedPantherStacks"

	e2eRuleBody = `
def rule(event):
    return True
`
	e2eDedupMinutes    = 2
	e2eRuleDescription = "E2E test - match all incoming logs"
	e2eRuleID          = "E2E.RandomLogMatch"
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
	// TODO - can we use testing library to make assertions

	ctx := e2eContext{
		FirstUserEmail: prompt.Read("Email for initial invite: ", prompt.EmailValidator),
	}

	// TODO - allow specifying STAGE to jump to

	// Make sure there are no leftover resources that would fail the deployment.
	logger.Info("***** test:e2e : Stage 1/8 : Pre-Teardown *****")
	// TODO - teardown masterStack as well?
	// TODO - mage clean setup?
	Teardown() // includes getSession()
	// I tried removing AWSService IAM roles here - AWS does not allow it

	ctx.GatewayClient = gatewayapi.GatewayClient(awsSession)
	ctx.Region = *awsSession.Config.Region
	ctx.deployPreviousVersion()
	ctx.interactWithOldVersion()
	ctx.migrate()
	ctx.validateMigration()

	// TODO - use a fresh account from AWS organizations for this
	// TODO - stage 6 - validate product functionality - enable policy/rule, verify alerts
	// TODO - stage 7 - integration test
	// TODO - stage 8 - teardown + verify no leftover resources
	// TODO - stage 9 - cleanup (bucket, IAM role, ecr repo)
}

// Deploy the official published pre-packaged deployment for the previous version.
func (ctx *e2eContext) deployPreviousVersion() {
	logger.Info("***** test:e2e : Stage 2/8 : Deploy Previous Release *****")
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
		"--parameter-overrides", "CompanyDisplayName="+e2eCompanyName, "FirstUserEmail="+ctx.FirstUserEmail,
		"FirstUserGivenName="+e2eFirstName, "FirstUserFamilyName="+e2eLastName,
		"--region", ctx.Region,
		"--stack-name", masterStackName,
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
	logger.Info("***** test:e2e : Stage 3/8 : Generate Data in Previous Release *****")

	// TODO - directly put a log into the ingestion bucket

	// Add an SQS alert destination
	queue, err := sqs.New(awsSession).CreateQueue(&sqs.CreateQueueInput{
		QueueName: aws.String("e2e-test"), // TODO - rename "panther-e2e-test" ?
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

	// TODO - modify an existing policy...

	// Add a policy which scans "panther-" stacks
	policy, err := ctx.AnalysisClient.Operations.CreatePolicy(&analysisops.CreatePolicyParams{
		Body: &analysismodels.UpdatePolicy{
			Body:          e2ePolicyBody,
			Description:   e2ePolicyDescription,
			Enabled:       false,
			ID:            e2ePolicyID,
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
			Body:               e2eRuleBody,
			DedupPeriodMinutes: e2eDedupMinutes,
			Description:        e2eRuleDescription,
			Enabled:            false,
			ID:                 e2eRuleID,
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

// Using the deployment role, migrate to the current master stack
func (ctx *e2eContext) migrate() {
	logger.Info("***** test:e2e : Stage 4/8 : Migrate to Current Master Template *****")

	// Create deployment role
	deploymentRoleTemplate := filepath.Join(
		"deployments", "auxiliary", "cloudformation", "panther-deployment-role.yml")
	logger.Infof("creating deployment role from %s", deploymentRoleTemplate)

	err := sh.RunV(filepath.Join(pythonVirtualEnvPath, "bin", "sam"), "deploy",
		"--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM",
		"--no-fail-on-empty-changeset",
		"--region", ctx.Region,
		"--stack-name", "panther-deployment-role",
		"--template", deploymentRoleTemplate,
	)
	if err != nil {
		logger.Fatal(err)
	}
	// TODO - we already got the accountID during the first teardown
	accountID := getAccountID()
	deploymentRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/PantherDeploymentRole", accountID)

	// Create S3 bucket and ECR repo for staging master package assets
	bucket := e2eResourceName + "-" + accountID
	if _, err := s3.New(awsSession).CreateBucket(&s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() != s3.ErrCodeBucketAlreadyExists && awsErr.Code() != s3.ErrCodeBucketAlreadyOwnedByYou {
			logger.Fatalf("failed to create S3 bucket %s: %v", bucket, err)
		}
	}

	_, err = ecr.New(awsSession).CreateRepository(&ecr.CreateRepositoryInput{
		RepositoryName: aws.String(e2eResourceName),
	})
	if err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() != ecr.ErrCodeRepositoryAlreadyExistsException {
			logger.Fatalf("failed to create ECR repository %s: %v", e2eResourceName, err)
		}
	}
	logger.Infof("created S3 bucket %s and ECR repo %s for staging master assets", bucket, e2eResourceName)

	// TODO - ensure master version is different from the one we deployed to trigger custom resource updates
	masterBuild()
	masterVersion := getMasterVersion()
	imgRegistry := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", accountID, ctx.Region, e2eResourceName)
	pkg := masterPackage(bucket, masterVersion, imgRegistry)

	// Deploy current master template to upgrade Panther to the release candidate
	logger.Infof("updating %s stack with local master template %s using IAM role %s",
		masterStackName, masterVersion, deploymentRoleArn)
	err = sh.RunV(filepath.Join(pythonVirtualEnvPath, "bin", "sam"), "deploy",
		"--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND",
		"--parameter-overrides", "ImageRegistry="+imgRegistry,
		"--region", ctx.Region,
		"--role-arn", deploymentRoleArn,
		"--stack-name", masterStackName,
		"--template", pkg,
	)
	if err != nil {
		logger.Fatal(err)
	}
}

// Ensure user data wasn't corrupted during the migration.
func (ctx *e2eContext) validateMigration() {
	logger.Info("***** test:e2e : Stage 5/8 : Validate Migration *****")

	// User list should still contain only the single invited user
	lambdaClient := lambda.New(awsSession)
	var userList usermodels.ListUsersOutput
	listInput := usermodels.LambdaInput{ListUsers: &usermodels.ListUsersInput{}}
	if err := genericapi.Invoke(lambdaClient, usersAPI, &listInput, &userList); err != nil {
		logger.Fatalf("failed to invoke %s.listUsers: %v", usersAPI, err)
	}
	if len(userList.Users) != 1 {
		logger.Fatalf("expected 1 Panther user, found %d", len(userList.Users))
	}
	user := userList.Users[0]
	if aws.StringValue(user.GivenName) != e2eFirstName || aws.StringValue(user.FamilyName) != e2eLastName {
		logger.Fatalf("expected Panther user %s %s, found %s %s (ID %s)",
			e2eFirstName, e2eLastName,
			aws.StringValue(user.GivenName), aws.StringValue(user.FamilyName),
			*user.ID)
	}

	// Organization settings
	var orgSettings orgmodels.GeneralSettings
	orgInput := orgmodels.LambdaInput{GetSettings: &orgmodels.GetSettingsInput{}}
	if err := genericapi.Invoke(lambdaClient, orgAPI, &orgInput, &orgSettings); err != nil {
		logger.Fatalf("failed to invoke %s.getSettings: %v", orgAPI, err)
	}
	if aws.StringValue(orgSettings.DisplayName) != e2eCompanyName {
		logger.Fatalf("expected org name \"%s\", found \"%s\"",
			e2eCompanyName, aws.StringValue(orgSettings.DisplayName))
	}

	// New policy should be the same
	policyResponse, err := ctx.AnalysisClient.Operations.GetPolicy(&analysisops.GetPolicyParams{
		PolicyID:   e2ePolicyID,
		HTTPClient: ctx.GatewayClient,
	})
	if err != nil {
		logger.Fatalf("failed to retrieve policy %s: %v", e2ePolicyID, err)
	}
	policy := policyResponse.Payload
	if policy.Enabled || policy.Body != e2ePolicyBody || policy.Description != e2ePolicyDescription {
		logger.Fatalf("policy ID %s unexpectedly changed", policy.ID)
	}
	// check rule
	// check output
}
