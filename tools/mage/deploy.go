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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	lpmodels "github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	orgmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	usermodels "github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/config"
)

const (
	// Bootstrap stacks
	bootstrapStack    = "panther-bootstrap"
	bootstrapTemplate = "deployments/bootstrap.yml"
	gatewayStack      = "panther-bootstrap-gateway"
	gatewayTemplate   = apiEmbeddedTemplate

	// Main stacks
	alarmsStack         = "panther-cw-alarms"
	alarmsTemplate      = "deployments/alarms.yml"
	appsyncStack        = "panther-appsync"
	appsyncTemplate     = "deployments/appsync.yml"
	cloudsecStack       = "panther-cloud-security"
	cloudsecTemplate    = "deployments/cloud_security.yml"
	coreStack           = "panther-core"
	coreTemplate        = "deployments/core.yml"
	dashboardStack      = "panther-cw-dashboards"
	dashboardTemplate   = "out/deployments/monitoring/dashboards.json"
	frontendStack       = "panther-web"
	frontendTemplate    = "deployments/web_server.yml"
	logAnalysisStack    = "panther-log-analysis"
	logAnalysisTemplate = "deployments/log_analysis.yml"
	metricFilterStack   = "panther-cw-metric-filters"
	onboardStack        = "panther-onboard"
	onboardTemplate     = "deployments/onboard.yml"

	// Python layer
	layerSourceDir        = "out/pip/analysis/python"
	layerZipfile          = "out/layer.zip"
	defaultGlobalID       = "panther"
	defaultGlobalLocation = "internal/compliance/policy_engine/src/helpers.py"

	mageUserID = "00000000-0000-4000-8000-000000000000" // used to indicate mage made the call, must be a valid uuid4!
)

// Not all AWS services are available in every region. In particular, Panther will currently NOT work in:
//     n. california, us-gov, china, paris, stockholm, brazil, osaka, or bahrain
// These regions are missing combinations of AppSync, Cognito, Athena, and/or Glue.
// https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services
var supportedRegions = map[string]bool{
	"ap-northeast-1": true, // tokyo
	"ap-northeast-2": true, // seoul
	"ap-south-1":     true, // mumbai
	"ap-southeast-1": true, // singapore
	"ap-southeast-2": true, // sydney
	"ca-central-1":   true, // canada
	"eu-central-1":   true, // frankfurt
	"eu-west-1":      true, // ireland
	"eu-west-2":      true, // london
	"us-east-1":      true, // n. virginia
	"us-east-2":      true, // ohio
	"us-west-2":      true, // oregon
}

// NOTE: Mage ignores the first word of the comment if it matches the function name.
// So the comment below is intentionally "Deploy Deploy"

// Deploy Deploy Panther to your AWS account
func Deploy() {
	start := time.Now()

	// ***** Step 0: load settings and AWS session and verify environment
	settings, err := config.Settings()
	if err != nil {
		logger.Fatalf("failed to read config file %s: %v", config.Filepath, err)
	}

	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}

	deployPrecheck(*awsSession.Config.Region)
	identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		logger.Fatalf("failed to get caller identity: %v", err)
	}
	accountID := *identity.Account
	logger.Infof("deploy: deploying Panther %s to account %s (%s)", gitVersion, accountID, *awsSession.Config.Region)

	// ***** Step 1: bootstrap stacks and build artifacts
	outputs := bootstrap(awsSession, settings)

	// ***** Step 2: deploy remaining stacks in parallel
	deployMainStacks(awsSession, settings, accountID, outputs)

	// ***** Step 3: first-time setup if needed
	if err := initializeAnalysisSets(awsSession, outputs["AnalysisApiEndpoint"], settings); err != nil {
		logger.Fatal(err)
	}
	if err := initializeGlobal(awsSession, outputs["AnalysisApiEndpoint"]); err != nil {
		logger.Fatal(err)
	}
	if err := inviteFirstUser(awsSession); err != nil {
		logger.Fatal(err)
	}

	// ***** Step 4: migrations
	// Starting in v1.3.0, the metric-filter stack is no longer used. It can be safely deleted
	if err := deleteStack(cloudformation.New(awsSession), aws.String(metricFilterStack)); err != nil {
		logger.Warnf("failed to delete deprecated %s stack: %v", metricFilterStack, err)
	}

	logger.Infof("deploy: finished successfully in %s", time.Since(start).Round(time.Second))
	logger.Infof("***** Panther URL = https://%s", outputs["LoadBalancerUrl"])
}

// Fail the deploy early if there is a known issue with the user's environment.
func deployPrecheck(awsRegion string) {
	// Ensure the AWS region is supported
	if !supportedRegions[awsRegion] {
		logger.Fatalf("panther is not supported in %s region", awsRegion)
	}

	// Check the Go version (1.12 fails with a build error)
	if version := runtime.Version(); version <= "go1.12" {
		logger.Fatalf("go %s not supported, upgrade to 1.13+", version)
	}

	// Make sure docker is running
	if _, err := sh.Output("docker", "info"); err != nil {
		logger.Fatalf("docker is not available: %v", err)
	}

	// Ensure swagger is available
	if _, err := sh.Output(filepath.Join(setupDirectory, "swagger"), "version"); err != nil {
		logger.Fatalf("swagger is not available (%v): try 'mage setup'", err)
	}

	// Set global gitVersion, warn if not deploying a tagged release
	var err error
	gitVersion, err = sh.Output("git", "describe", "--tags")
	if err != nil {
		logger.Fatalf("git describe failed: %v", err)
	}
	// The gitVersion is "v0.3.0" on tagged release, otherwise something like "v0.3.0-128-g77fd9ff"
	if strings.Contains(gitVersion, "-") {
		logger.Warnf("%s is not a tagged release, proceed at your own risk", gitVersion)
	}
}

// Deploy bootstrap stacks and build deployment artifacts.
//
// Returns combined outputs from bootstrap stacks.
func bootstrap(awsSession *session.Session, settings *config.PantherConfig) map[string]string {
	build.API()
	build.Cfn()
	build.Lambda() // Lambda compilation required for most stacks, including bootstrap-gateway

	// Deploy bootstrap stacks
	outputs, err := deployBoostrapStacks(awsSession, settings)
	if err != nil {
		logger.Fatal(err)
	}

	return outputs
}

// Deploy bootstrap and bootstrap-gateway and merge their outputs
func deployBoostrapStacks(
	awsSession *session.Session,
	settings *config.PantherConfig,
) (map[string]string, error) {

	params := map[string]string{
		"LogSubscriptionPrincipals":  strings.Join(settings.Setup.LogSubscriptions.PrincipalARNs, ","),
		"EnableS3AccessLogs":         strconv.FormatBool(settings.Setup.EnableS3AccessLogs),
		"AccessLogsBucket":           settings.Setup.S3AccessLogsBucket,
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomDomain":               settings.Web.CustomDomain,
		"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
		"TracingMode":                settings.Monitoring.TracingMode,
		"AlarmTopicArn":              settings.Monitoring.AlarmSnsTopicArn,
	}

	outputs, err := deployTemplate(awsSession, bootstrapTemplate, "", bootstrapStack, params)
	if err != nil {
		return nil, err
	}

	logger.Infof("    √ %s finished (1/%d)", bootstrapStack, len(allStacks))

	// Now that the S3 buckets are in place, we can deploy the second bootstrap stack.
	if err = buildLayer(settings.Infra.PipLayer); err != nil {
		return nil, err
	}

	sourceBucket := outputs["SourceBucket"]
	params = map[string]string{
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"PythonLayerVersionArn":      settings.Infra.PythonLayerVersionArn,
		"TracingMode":                settings.Monitoring.TracingMode,
		"UserPoolId":                 outputs["UserPoolId"],
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
	}

	// Deploy second bootstrap stack and merge outputs
	gatewayOutputs, err := deployTemplate(awsSession, gatewayTemplate, sourceBucket, gatewayStack, params)
	if err != nil {
		return nil, err
	}

	for k, v := range gatewayOutputs {
		if _, exists := outputs[k]; exists {
			return nil, fmt.Errorf("output %s exists in both bootstrap stacks", k)
		}
		outputs[k] = v
	}

	logger.Infof("    √ %s finished (2/%d)", gatewayStack, len(allStacks))
	return outputs, nil
}

// Build standard Python analysis layer in out/layer.zip if that file doesn't already exist.
func buildLayer(libs []string) error {
	if _, err := os.Stat(layerZipfile); err == nil {
		logger.Debugf("%s already exists, not rebuilding layer")
		return nil
	}

	logger.Info("deploy: downloading python libraries " + strings.Join(libs, ","))
	if err := os.RemoveAll(layerSourceDir); err != nil {
		return fmt.Errorf("failed to remove layer directory %s: %v", layerSourceDir, err)
	}
	if err := os.MkdirAll(layerSourceDir, 0755); err != nil {
		return fmt.Errorf("failed to create layer directory %s: %v", layerSourceDir, err)
	}
	args := append([]string{"install", "-t", layerSourceDir}, libs...)
	if err := sh.Run("pip3", args...); err != nil {
		return fmt.Errorf("failed to download pip libraries: %v", err)
	}

	// The package structure needs to be:
	//
	// layer.zip
	// │ python/policyuniverse/
	// └ python/policyuniverse-VERSION.dist-info/
	//
	// https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path
	if err := shutil.ZipDirectory(filepath.Dir(layerSourceDir), layerZipfile, false); err != nil {
		return fmt.Errorf("failed to zip %s into %s: %v", layerSourceDir, layerZipfile, err)
	}

	return nil
}

// Deploy main stacks
//
// In parallel: alarms, appsync, cloudsec, core, dashboards, glue, log analysis, web
// Then metric-filters and onboarding at the end
//
// nolint: funlen
func deployMainStacks(awsSession *session.Session, settings *config.PantherConfig, accountID string, outputs map[string]string) {
	sourceBucket := outputs["SourceBucket"]
	results := make(chan goroutineResult)
	count := 0

	// Alarms
	count++
	go func(c chan goroutineResult) {
		_, err := deployTemplate(awsSession, alarmsTemplate, sourceBucket, alarmsStack, map[string]string{
			"AlarmTopicArn": outputs["AlarmTopicArn"],
		})
		c <- goroutineResult{summary: alarmsStack, err: err}
	}(results)

	// Appsync
	count++
	go func(c chan goroutineResult) {
		_, err := deployTemplate(awsSession, appsyncTemplate, sourceBucket, appsyncStack, map[string]string{
			"ApiId":          outputs["GraphQLApiId"],
			"AlarmTopicArn":  outputs["AlarmTopicArn"],
			"ServiceRole":    outputs["AppsyncServiceRoleArn"],
			"AnalysisApi":    "https://" + outputs["AnalysisApiEndpoint"],
			"ComplianceApi":  "https://" + outputs["ComplianceApiEndpoint"],
			"RemediationApi": "https://" + outputs["RemediationApiEndpoint"],
			"ResourcesApi":   "https://" + outputs["ResourcesApiEndpoint"],
		})
		c <- goroutineResult{summary: appsyncStack, err: err}
	}(results)

	// Cloud security
	count++
	go func(c chan goroutineResult) {
		_, err := deployTemplate(awsSession, cloudsecTemplate, sourceBucket, cloudsecStack, map[string]string{
			"AlarmTopicArn":         outputs["AlarmTopicArn"],
			"AnalysisApiId":         outputs["AnalysisApiId"],
			"ComplianceApiId":       outputs["ComplianceApiId"],
			"RemediationApiId":      outputs["RemediationApiId"],
			"ResourcesApiId":        outputs["ResourcesApiId"],
			"ProcessedDataTopicArn": outputs["ProcessedDataTopicArn"],
			"ProcessedDataBucket":   outputs["ProcessedDataBucket"],
			"PythonLayerVersionArn": outputs["PythonLayerVersionArn"],
			"SqsKeyId":              outputs["QueueEncryptionKeyId"],

			"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
			"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
			"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
			"TracingMode":                settings.Monitoring.TracingMode,
		})
		c <- goroutineResult{summary: cloudsecStack, err: err}
	}(results)

	// Core
	count++
	go func(c chan goroutineResult) {
		_, err := deployTemplate(awsSession, coreTemplate, sourceBucket, coreStack, map[string]string{
			"AlarmTopicArn":          outputs["AlarmTopicArn"],
			"AppDomainURL":           outputs["LoadBalancerUrl"],
			"AnalysisVersionsBucket": outputs["AnalysisVersionsBucket"],
			"AnalysisApiId":          outputs["AnalysisApiId"],
			"AthenaResultsBucket":    outputs["AthenaResultsBucket"],
			"ComplianceApiId":        outputs["ComplianceApiId"],
			"DynamoScalingRoleArn":   outputs["DynamoScalingRoleArn"],
			"ProcessedDataBucket":    outputs["ProcessedDataBucket"],
			"OutputsKeyId":           outputs["OutputsEncryptionKeyId"],
			"SqsKeyId":               outputs["QueueEncryptionKeyId"],
			"UserPoolId":             outputs["UserPoolId"],

			"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
			"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
			"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
			"TracingMode":                settings.Monitoring.TracingMode,
		})
		c <- goroutineResult{summary: coreStack, err: err}
	}(results)

	// Dashboards
	count++
	go func(c chan goroutineResult) {
		_, err := deployTemplate(awsSession, dashboardTemplate, sourceBucket, dashboardStack, nil)
		c <- goroutineResult{summary: dashboardStack, err: err}
	}(results)

	// Log analysis
	count++
	go func(c chan goroutineResult) {
		_, err := deployTemplate(awsSession, logAnalysisTemplate, sourceBucket, logAnalysisStack, map[string]string{
			"AlarmTopicArn":         outputs["AlarmTopicArn"],
			"AnalysisApiId":         outputs["AnalysisApiId"],
			"ProcessedDataBucket":   outputs["ProcessedDataBucket"],
			"ProcessedDataTopicArn": outputs["ProcessedDataTopicArn"],
			"PythonLayerVersionArn": outputs["PythonLayerVersionArn"],
			"SqsKeyId":              outputs["QueueEncryptionKeyId"],

			"CloudWatchLogRetentionDays":   strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
			"Debug":                        strconv.FormatBool(settings.Monitoring.Debug),
			"LayerVersionArns":             settings.Infra.BaseLayerVersionArns,
			"LogProcessorLambdaMemorySize": strconv.Itoa(settings.Infra.LogProcessorLambdaMemorySize),
			"TracingMode":                  settings.Monitoring.TracingMode,
		})
		c <- goroutineResult{summary: logAnalysisStack, err: err}
	}(results)

	// Web server
	count++
	go func(c chan goroutineResult) {
		_, err := deployFrontend(awsSession, accountID, sourceBucket, outputs, settings)
		c <- goroutineResult{summary: frontendStack, err: err}
	}(results)

	// Glue (not a stack!, moving to custom resource)
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{summary: "panther-glue-tables", err: deployGlue(awsSession, outputs)}
	}(results)

	// Wait for stacks to finish.
	// There are two stacks before and one stack after
	logResults(results, "deploy", 3, count+2, len(allStacks)+1)

	// Onboard Panther to scan itself
	go func(c chan goroutineResult) {
		var err error
		if settings.Setup.OnboardSelf {
			err = deployOnboard(awsSession, settings, accountID, outputs)
		}
		c <- goroutineResult{summary: onboardStack, err: err}
	}(results)

	// Log stack results, counting where the last parallel group left off to give the illusion of
	// one continuous deploy progress tracker.
	logResults(results, "deploy", count+3, len(allStacks)+1, len(allStacks)+1)
}

func deployGlue(awsSession *session.Session, outputs map[string]string) error {
	glueClient := glue.New(awsSession)
	s3Client := s3.New(awsSession)
	for pantherDatabase, pantherDatabaseDescription := range awsglue.PantherDatabases {
		logger.Infof("deploy: creating database %s", pantherDatabase)
		_, err := awsglue.CreateDatabase(glueClient, pantherDatabase, pantherDatabaseDescription)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeAlreadyExistsException {
				logger.Infof("deploy: database %s already exists", pantherDatabase)
			} else {
				logger.Fatal(err)
			}
		}
	}

	logger.Info("deploy: configuring Athena")
	// Workgroup "primary" is default.
	const workgroup = "primary"
	athenaBucket := outputs["AthenaResultsBucket"]
	if err := awsathena.WorkgroupAssociateS3(awsSession, workgroup, athenaBucket); err != nil {
		return fmt.Errorf("failed to associate %s Athena workgroup with %s bucket: %v", workgroup, athenaBucket, err)
	}

	// update schemas for tables that are deployed
	var zeroStartTime time.Time // setting the startTime to 0, means use createTime for the table
	deployedLogTables, err := gluetables.DeployedTables(glueClient)
	if err != nil {
		logger.Fatal(err)
	}
	for _, logTable := range deployedLogTables {
		logger.Infof("deploy: creating/updating glue table %s.%s",
			logTable.DatabaseName(), logTable.TableName())
		err := logTable.CreateOrUpdateTable(glueClient, outputs["ProcessedDataBucket"])
		if err != nil {
			return errors.Wrapf(err, "could not create glue log table for %s.%s",
				logTable.DatabaseName(), logTable.TableName())
		}
		err = logTable.SyncPartitions(glueClient, s3Client, zeroStartTime)
		if err != nil {
			logger.Fatalf("deploy: failed syncing %s.%s: %v",
				logTable.DatabaseName(), logTable.TableName(), err)
		}

		// the corresponding rule table shares the same structure as the log table + some columns
		ruleTable := awsglue.NewGlueTableMetadata(
			lpmodels.RuleData, logTable.LogType(), logTable.Description(), awsglue.GlueTableHourly, logTable.EventStruct())
		logger.Infof("deploy: creating/updating glue table %s.%s",
			ruleTable.DatabaseName(), ruleTable.TableName())
		err = ruleTable.CreateOrUpdateTable(glueClient, outputs["ProcessedDataBucket"])
		if err != nil {
			return errors.Wrapf(err, "could not create glue rule table for %s.%s",
				ruleTable.DatabaseName(), ruleTable.TableName())
		}
		err = ruleTable.SyncPartitions(glueClient, s3Client, zeroStartTime)
		if err != nil {
			logger.Fatalf("deploy: failed syncing %s.%s: %v",
				ruleTable.DatabaseName(), ruleTable.TableName(), err)
		}
	}

	logger.Info("deploy: DONE!")

	return nil
}

// If the users list is empty (e.g. on the initial deploy), create the first user.
func inviteFirstUser(awsSession *session.Session) error {
	input := &usermodels.LambdaInput{
		ListUsers: &usermodels.ListUsersInput{},
	}
	var output usermodels.ListUsersOutput
	if err := invokeLambda(awsSession, "panther-users-api", input, &output); err != nil {
		return fmt.Errorf("failed to list users: %v", err)
	}
	if len(output.Users) > 0 {
		return nil
	}

	// Prompt the user for basic information.
	logger.Info("setting up initial Panther admin user...")
	fmt.Println()
	firstName := promptUser("First name: ", nonemptyValidator)
	lastName := promptUser("Last name: ", nonemptyValidator)
	email := promptUser("Email: ", emailValidator)
	defaultOrgName := firstName + "-" + lastName
	orgName := promptUser("Company/Team name ("+defaultOrgName+"): ", nil)
	if orgName == "" {
		orgName = defaultOrgName
	}

	// users-api.InviteUser
	input = &usermodels.LambdaInput{
		InviteUser: &usermodels.InviteUserInput{
			GivenName:  &firstName,
			FamilyName: &lastName,
			Email:      &email,
		},
	}
	if err := invokeLambda(awsSession, "panther-users-api", input, nil); err != nil {
		return err
	}
	logger.Infof("invite sent to %s: check your email! (it may be in spam)", email)

	// organizations-api.UpdateSettings
	updateSettingsInput := &orgmodels.LambdaInput{
		UpdateSettings: &orgmodels.UpdateSettingsInput{DisplayName: &orgName, Email: &email},
	}
	return invokeLambda(awsSession, "panther-organization-api", &updateSettingsInput, nil)
}

// Install Python rules/policies if they don't already exist.
func initializeAnalysisSets(awsSession *session.Session, endpoint string, settings *config.PantherConfig) error {
	httpClient := gatewayapi.GatewayClient(awsSession)
	apiClient := client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(endpoint))

	policies, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		PageSize:   aws.Int64(1),
		HTTPClient: httpClient,
	})
	if err != nil {
		return fmt.Errorf("failed to list existing policies: %v", err)
	}

	rules, err := apiClient.Operations.ListRules(&operations.ListRulesParams{
		PageSize:   aws.Int64(1),
		HTTPClient: httpClient,
	})
	if err != nil {
		return fmt.Errorf("failed to list existing rules: %v", err)
	}

	if len(policies.Payload.Policies) > 0 || len(rules.Payload.Rules) > 0 {
		logger.Debug("deploy: initial analysis set ignored: policies and/or rules already exist")
		return nil
	}

	var newRules, newPolicies int64
	for _, path := range settings.Setup.InitialAnalysisSets {
		logger.Info("deploy: uploading initial analysis pack " + path)
		var contents []byte
		if strings.HasPrefix(path, "file://") {
			contents = readFile(strings.TrimPrefix(path, "file://"))
		} else {
			contents, err = download(path)
			if err != nil {
				return err
			}
		}

		// BulkUpload to panther-analysis-api
		encoded := base64.StdEncoding.EncodeToString(contents)
		response, err := apiClient.Operations.BulkUpload(&operations.BulkUploadParams{
			Body: &analysismodels.BulkUpload{
				Data:   analysismodels.Base64zipfile(encoded),
				UserID: mageUserID,
			},
			HTTPClient: httpClient,
		})
		if err != nil {
			return fmt.Errorf("failed to upload %s: %v", path, err)
		}

		newRules += *response.Payload.NewRules
		newPolicies += *response.Payload.NewPolicies
	}

	logger.Infof("deploy: initialized with %d policies and %d rules", newPolicies, newRules)
	return nil
}

// Install the default global helper function if it does not already exist
func initializeGlobal(awsSession *session.Session, endpoint string) error {
	httpClient := gatewayapi.GatewayClient(awsSession)
	apiClient := client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(endpoint))

	_, err := apiClient.Operations.GetGlobal(&operations.GetGlobalParams{
		GlobalID:   defaultGlobalID,
		HTTPClient: httpClient,
	})
	// Global already exists
	if err == nil {
		logger.Debug("deploy: global module already exists")
		return nil
	}

	// Return errors other than 404 not found
	if _, ok := err.(*operations.GetGlobalNotFound); !ok {
		return fmt.Errorf("failed to get existing global file: %v", err)
	}

	// Setup the initial helper layer
	content, err := ioutil.ReadFile(defaultGlobalLocation)
	if err != nil {
		return fmt.Errorf("failed to read default globals file: %v", err)
	}

	logger.Infof("deploy: uploading initial global helper module")
	_, err = apiClient.Operations.CreateGlobal(&operations.CreateGlobalParams{
		Body: &analysismodels.UpdateGlobal{
			Body:        analysismodels.Body(string(content)),
			Description: "A set of default helper functions.",
			ID:          defaultGlobalID,
			UserID:      mageUserID,
		},
		HTTPClient: httpClient,
	})

	if err != nil {
		return fmt.Errorf("failed to upload default globals file: %v", err)
	}

	return nil
}
