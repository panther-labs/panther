package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/fatih/color"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	orgmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	usermodels "github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/athenaviews"
	"github.com/panther-labs/panther/tools/config"
)

const (
	// Bootstrap stacks
	bootstrapStack    = "panther-bootstrap"
	bootstrapTemplate = "deployments/bootstrap.yml"
	gatewayStack      = "panther-bootstrap-gateway"
	gatewayTemplate   = apiEmbeddedTemplate

	// Main stacks
	alarmsStack          = "panther-cw-alarms"
	alarmsTemplate       = "deployments/alarms.yml"
	appsyncStack         = "panther-appsync"
	appsyncTemplate      = "deployments/appsync.yml"
	cloudsecStack        = "panther-cloud-security"
	cloudsecTemplate     = "deployments/cloud_security.yml"
	coreStack            = "panther-core"
	coreTemplate         = "deployments/core.yml"
	dashboardStack       = "panther-cw-dashboards"
	dashboardTemplate    = "out/deployments/monitoring/dashboards.json"
	frontendStack        = "panther-web"
	frontendTemplate     = "deployments/web_server.yml"
	glueStack            = "panther-glue"
	glueTemplate         = "out/deployments/gluetables.json"
	logAnalysisStack     = "panther-log-analysis"
	logAnalysisTemplate  = "deployments/log_analysis.yml"
	metricFilterStack    = "panther-cw-metric-filters"
	metricFilterTemplate = "out/deployments/monitoring/metrics.json"
	onboardStack         = "panther-onboard"
	onboardTemplate      = "deployments/onboard.yml"

	// Python layer
	layerSourceDir   = "out/pip/analysis/python"
	layerZipfile     = "out/layer.zip"
	layerS3ObjectKey = "layers/python-analysis.zip"

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

// Deploy Deploy application infrastructure
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
	logger.Infof("deploy: deploying Panther to account %s (%s)", accountID, *awsSession.Config.Region)

	// ***** Step 1: bootstrap stacks and build artifacts
	outputs := bootstrap(awsSession, settings)

	// ***** Step 2: deploy remaining stacks in parallel
	deployMainStacks(awsSession, settings, accountID, outputs)

	// ***** Step 3: first-time setup if needed
	if err := initializeAnalysisSets(awsSession, outputs["AnalysisApiEndpoint"], settings); err != nil {
		logger.Fatal(err)
	}
	if err := inviteFirstUser(awsSession); err != nil {
		logger.Fatal(err)
	}

	logger.Infof("deploy: finished successfully in %s", time.Since(start))
	color.Yellow("\nPanther URL = https://%s\n", outputs["LoadBalancerUrl"])
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
		logger.Fatalf("swagger is not available (%v): try 'mage setup:swagger'", err)
	}

	// Warn if not deploying a tagged release
	output, err := sh.Output("git", "describe", "--tags")
	if err != nil {
		logger.Fatalf("git describe failed: %v", err)
	}
	// The output is "v0.3.0" on tagged release, otherwise something like "v0.3.0-128-g77fd9ff"
	if strings.Contains(output, "-") {
		logger.Warnf("%s is not a tagged release, proceed at your own risk", output)
	}
}

// Deploy bootstrap stacks and build deployment artifacts.
//
// Returns combined outputs from bootstrap stacks.
func bootstrap(awsSession *session.Session, settings *config.PantherConfig) map[string]string {
	var outputs map[string]string
	var wg sync.WaitGroup
	wg.Add(1)

	// Deploy first bootstrap stack
	go func() {
		params := map[string]string{
			"EnableS3AccessLogs":         strconv.FormatBool(settings.Setup.EnableS3AccessLogs),
			"AccessLogsBucket":           settings.Setup.S3AccessLogsBucket,
			"CertificateArn":             certificateArn(awsSession, settings),
			"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
			"CustomDomain":               settings.Web.CustomDomain,
			"TracingMode":                settings.Monitoring.TracingMode,
		}

		outputs = deployTemplate(awsSession, bootstrapTemplate, "", bootstrapStack, params)

		// Enable software 2FA for the Cognito user pool - this is not yet supported in CloudFormation.
		userPoolID := outputs["UserPoolId"]
		logger.Debugf("deploy: enabling TOTP for user pool %s", userPoolID)
		_, err := cognitoidentityprovider.New(awsSession).SetUserPoolMfaConfig(&cognitoidentityprovider.SetUserPoolMfaConfigInput{
			MfaConfiguration: aws.String("ON"),
			SoftwareTokenMfaConfiguration: &cognitoidentityprovider.SoftwareTokenMfaConfigType{
				Enabled: aws.Bool(true),
			},
			UserPoolId: &userPoolID,
		})
		if err != nil {
			logger.Fatalf("failed to enable TOTP for user pool %s: %v", userPoolID, err)
		}

		wg.Done()
	}()

	// While waiting for bootstrap, build deployment artifacts
	var build Build
	build.Cfn()
	build.Lambda()
	wg.Wait()

	// Now that the S3 buckets are in place and swagger specs are embedded, we can deploy the second
	// bootstrap stack (API gateways and the Python layer).
	sourceBucket := outputs["SourceBucket"]
	params := map[string]string{
		"TracingEnabled": strconv.FormatBool(settings.Monitoring.TracingMode != ""),
	}

	if settings.Infra.PythonLayerVersionArn == "" {
		// Build default layer
		params["SourceBucket"] = sourceBucket
		params["PythonLayerKey"] = layerS3ObjectKey
		params["PythonLayerObjectVersion"] = uploadLayer(awsSession, settings.Infra.PipLayer, sourceBucket, layerS3ObjectKey)
	} else {
		// Use configured custom layer
		params["PythonLayerVersionArn"] = settings.Infra.PythonLayerVersionArn
	}

	// Deploy second bootstrap stack and merge outputs
	for k, v := range deployTemplate(awsSession, gatewayTemplate, sourceBucket, gatewayStack, params) {
		if _, exists := outputs[k]; exists {
			logger.Fatalf("output %s exists in both bootstrap stacks", k)
		}
		outputs[k] = v
	}

	return outputs
}

// Upload custom Python analysis layer to S3 (if it isn't already), returning version ID
func uploadLayer(awsSession *session.Session, libs []string, bucket, key string) string {
	s3Client := s3.New(awsSession)
	head, err := s3Client.HeadObject(&s3.HeadObjectInput{Bucket: &bucket, Key: &key})

	sort.Strings(libs)
	libString := strings.Join(libs, ",")
	if err == nil && aws.StringValue(head.Metadata["Libs"]) == libString {
		logger.Debugf("deploy: s3://%s/%s exists and is up to date", bucket, key)
		return *head.VersionId
	}

	// The layer is re-uploaded only if it doesn't exist yet or the library versions changed.
	logger.Info("deploy: downloading python libraries " + libString)
	if err := os.RemoveAll(layerSourceDir); err != nil {
		logger.Fatalf("failed to remove layer directory %s: %v", layerSourceDir, err)
	}
	if err := os.MkdirAll(layerSourceDir, 0755); err != nil {
		logger.Fatalf("failed to create layer directory %s: %v", layerSourceDir, err)
	}
	args := append([]string{"install", "-t", layerSourceDir}, libs...)
	if err := sh.Run("pip3", args...); err != nil {
		logger.Fatalf("failed to download pip libraries: %v", err)
	}

	// The package structure needs to be:
	//
	// layer.zip
	// │ python/policyuniverse/
	// └ python/policyuniverse-VERSION.dist-info/
	//
	// https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path
	if err := shutil.ZipDirectory(filepath.Dir(layerSourceDir), layerZipfile); err != nil {
		logger.Fatalf("failed to zip %s into %s: %v", layerSourceDir, layerZipfile, err)
	}

	// Upload to S3
	result, err := uploadFileToS3(awsSession, layerZipfile, bucket, key, map[string]*string{"Libs": &libString})
	if err != nil {
		logger.Fatalf("failed to upload %s to S3: %v", layerZipfile, err)
	}
	return *result.VersionID
}

// Deploy main stacks
//
// In parallel: alarms, appsync, cloudsec, core, dashboards, glue, log analysis, web
// Then metric-filters and onboarding at the end
//
// nolint: funlen
func deployMainStacks(awsSession *session.Session, settings *config.PantherConfig, accountID string, outputs map[string]string) {
	finishedStacks := make(chan string)
	sourceBucket := outputs["SourceBucket"]
	parallelStacks := 0

	// Alarms
	parallelStacks++
	go func(result chan string) {
		deployTemplate(awsSession, alarmsTemplate, sourceBucket, alarmsStack, map[string]string{
			"AppsyncId":            outputs["GraphQLApiId"],
			"LoadBalancerFullName": outputs["LoadBalancerFullName"],
			"AlarmTopicArn":        settings.Monitoring.AlarmSnsTopicArn,
		})
		result <- alarmsStack
	}(finishedStacks)

	// Appsync
	parallelStacks++
	go func(result chan string) {
		deployTemplate(awsSession, appsyncTemplate, sourceBucket, appsyncStack, map[string]string{
			"ApiId":          outputs["GraphQLApiId"],
			"ServiceRole":    outputs["AppsyncServiceRoleArn"],
			"AnalysisApi":    "https://" + outputs["AnalysisApiEndpoint"],
			"ComplianceApi":  "https://" + outputs["ComplianceApiEndpoint"],
			"RemediationApi": "https://" + outputs["RemediationApiEndpoint"],
			"ResourcesApi":   "https://" + outputs["ResourcesApiEndpoint"],
		})
		result <- appsyncStack
	}(finishedStacks)

	// Cloud security
	parallelStacks++
	go func(result chan string) {
		deployTemplate(awsSession, cloudsecTemplate, sourceBucket, cloudsecStack, map[string]string{
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
		result <- cloudsecStack
	}(finishedStacks)

	// Core
	parallelStacks++
	go func(result chan string) {
		deployTemplate(awsSession, coreTemplate, sourceBucket, coreStack, map[string]string{
			"AppDomainURL":           outputs["LoadBalancerUrl"],
			"AnalysisVersionsBucket": outputs["AnalysisVersionsBucket"],
			"AnalysisApiId":          outputs["AnalysisApiId"],
			"ComplianceApiId":        outputs["ComplianceApiId"],
			"OutputsKeyId":           outputs["OutputsEncryptionKeyId"],
			"SqsKeyId":               outputs["QueueEncryptionKeyId"],
			"UserPoolId":             outputs["UserPoolId"],

			"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
			"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
			"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
			"TracingMode":                settings.Monitoring.TracingMode,
		})
		result <- coreStack
	}(finishedStacks)

	// Dashboards
	parallelStacks++
	go func(result chan string) {
		deployTemplate(awsSession, dashboardTemplate, sourceBucket, dashboardStack, nil)
		result <- dashboardStack
	}(finishedStacks)

	// Glue
	parallelStacks++
	go func(result chan string) {
		deployGlue(awsSession, outputs)
		result <- glueStack
	}(finishedStacks)

	// Log analysis
	parallelStacks++
	go func(result chan string) {
		deployTemplate(awsSession, logAnalysisTemplate, sourceBucket, logAnalysisStack, map[string]string{
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
		result <- logAnalysisStack
	}(finishedStacks)

	// Web server
	parallelStacks++
	go func(result chan string) {
		deployFrontend(awsSession, accountID, sourceBucket, outputs)
		result <- frontendStack
	}(finishedStacks)

	// Wait for stacks to finish
	// There will be two stacks (onboarding + monitoring) after this one
	for i := 1; i <= parallelStacks; i++ {
		logger.Infof("    √ stack %s finished (%d/%d)", <-finishedStacks, i, parallelStacks+2)
	}

	// Metric filters have to be deployed after all log groups have been created
	go func(result chan string) {
		deployTemplate(awsSession, metricFilterTemplate, sourceBucket, metricFilterStack, nil)
		result <- metricFilterStack
	}(finishedStacks)

	// Onboard Panther to scan itself
	go func(result chan string) {
		if settings.Setup.OnboardSelf {
			deployOnboard(awsSession, settings, accountID, outputs)
		}
		result <- onboardStack
	}(finishedStacks)

	// Wait for onboarding and monitoring to finish
	for i := parallelStacks + 1; i <= parallelStacks+2; i++ {
		logger.Infof("    √ stack %s finished (%d/%d)", <-finishedStacks, i, parallelStacks+2)
	}
}

func deployGlue(awsSession *session.Session, outputs map[string]string) {
	deployTemplate(awsSession, glueTemplate, outputs["SourceBucket"], glueStack, map[string]string{
		"ProcessedDataBucket": outputs["ProcessedDataBucket"],
	})

	// Athena views are created via API call because CF is not well supported. Workgroup "primary" is default.
	const workgroup = "primary"
	athenaBucket := outputs["AthenaResultsBucket"]
	if err := awsathena.WorkgroupAssociateS3(awsSession, workgroup, athenaBucket); err != nil {
		logger.Fatalf("failed to associate %s Athena workgroup with %s bucket: %v", workgroup, athenaBucket, err)
	}
	if err := athenaviews.CreateOrReplaceViews(athenaBucket); err != nil {
		logger.Fatalf("failed to create/replace athena views for %s bucket: %v", athenaBucket, err)
	}
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
