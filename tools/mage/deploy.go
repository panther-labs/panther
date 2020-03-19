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
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/athenaviews"
	"github.com/panther-labs/panther/tools/config"
)

const (
	// CloudFormation templates + stacks
	bootstrapStack    = "panther-bootstrap"
	bootstrapTemplate = "deployments/bootstrap.yml"
	gatewayStack      = "panther-bootstrap2"
	gatewayTemplate   = apiEmbeddedTemplate

	appsyncStack       = "panther-appsync"
	appsyncTemplate    = "deployments/appsync.yml"
	coreStack          = "panther-core"
	coreTemplate       = "deployments/core.yml"
	glueStack          = "panther-glue"
	glueTemplate       = "out/deployments/gluetables.json"
	monitoringStack    = "panther-monitoring"
	monitoringTemplate = "deployments/monitoring.yml"

	// OLD ...
	backendStack    = "panther-app"
	backendTemplate = "deployments/backend.yml"
	bucketStack     = "panther-buckets" // prereq stack with Panther S3 buckets
	bucketTemplate  = "deployments/core/buckets.yml"

	// Python layer
	layerSourceDir   = "out/pip/analysis/python"
	layerZipfile     = "out/layer.zip"
	layerS3ObjectKey = "layers/python-analysis.zip"

	// CloudSec IAM Roles, DO NOT CHANGE! panther-compliance-iam.yml CF depends on these names
	auditRole       = "PantherAuditRole"
	remediationRole = "PantherRemediationRole"

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

	// ***** Step 1: bootstrap stack, generate CFN, compile Lambda functions
	outputs := bootstrap(awsSession)

	// ***** Step 2: deploy api gateway (template is large and must be uploaded to S3)
	// TODO: parameters (TracingEnabled)
	gatewayOutputs := deployTemplate(awsSession, gatewayTemplate, outputs["SourceBucket"], gatewayStack, nil)

	// ***** Step 3: deploy remaining stacks in parallel
	deployMainStacks(awsSession, settings, accountID, outputs, gatewayOutputs)

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	//// Deploy prerequisite bucket stack
	//bucketParams := map[string]string{
	//	"AccessLogsBucketName": config.BucketsParameterValues.AccessLogsBucketName,
	//}
	//bucketOutputs := deployTemplate(awsSession, bucketTemplate, "", bucketStack, bucketParams)
	//bucket := bucketOutputs["SourceBucketName"]
	//
	//// Deploy main application stack
	//params := getBackendDeployParams(awsSession, &config, bucket, bucketOutputs["LogBucketName"])
	//backendOutputs := deployTemplate(awsSession, backendTemplate, bucket, backendStack, params)
	//if err := postDeploySetup(awsSession, backendOutputs, &config); err != nil {
	//	logger.Fatal(err)
	//}
	//
	//
	//// Onboard Panther account to Panther
	//if config.OnboardParameterValues.OnboardSelf {
	//	runDeploy(func() { deployOnboard(awsSession, bucket, backendOutputs) })
	//}
	//
	//wg.Wait()
	//
	//// Done!
	logger.Infof("deploy: finished successfully in %s", time.Since(start))
	//color.Yellow("\nPanther URL = https://%s\n", backendOutputs["LoadBalancerUrl"])
}

// Fail the deploy early if there is a known issue with the user's environment.
func deployPrecheck(awsRegion string) {
	// Check the Go version (1.12 fails with a build error)
	if version := runtime.Version(); version <= "go1.12" {
		logger.Fatalf("go %s not supported, upgrade to 1.13+", version)
	}

	// Make sure docker is running
	if _, err := sh.Output("docker", "info"); err != nil {
		logger.Fatalf("docker is not available: %v", err)
	}

	// Ensure the AWS region is supported
	if !supportedRegions[awsRegion] {
		logger.Fatalf("panther is not supported in %s region", awsRegion)
	}
}

// In parallel, deploy bootstrap.yml and build lambda source + cfn templates
//
// Returns outputs from bootstrap stack
func bootstrap(awsSession *session.Session) map[string]string {
	var outputs map[string]string
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		// TODO: proper parameters loaded from config file
		params := map[string]string{"CertificateArn": "arn:aws:acm:us-west-2:101802775469:certificate/6e51b91b-0d7d-4592-89a3-c113c78e3ab3"} //uploadLocalCertificate(awsSession)}
		outputs = deployTemplate(awsSession, bootstrapTemplate, "", bootstrapStack, params)
		wg.Done()
	}()

	go func() {
		// TODO: swagger requires changing the working directory, which may not work well in parallel with ^
		var b Build
		// we don't build optools, takes too long and not required for deploy
		b.Lambda()
		b.Cfn()
		wg.Done()
	}()

	wg.Wait()
	return outputs
}

// Deploy main stacks in parallel: glue, web, monitoring, appsync, core, cloud security, log analysis
func deployMainStacks(
	awsSession *session.Session,
	settings *config.PantherConfig,
	accountID string,
	bootstrapOutputs map[string]string,
	gatewayOutputs map[string]string,
) {

	// TODO - this might make more sense if goroutines return (stack name, outputs) instead of sync group

	var wg sync.WaitGroup
	wg.Add(5)

	sourceBucket := bootstrapOutputs["SourceBucket"]

	// Appsync
	go func() {
		deployTemplate(awsSession, appsyncTemplate, sourceBucket, appsyncStack, map[string]string{
			"ApiId":          bootstrapOutputs["GraphQLApiId"],
			"ServiceRole":    bootstrapOutputs["AppsyncServiceRoleArn"],
			"AnalysisApi":    gatewayOutputs["AnalysisApiEndpoint"],
			"ComplianceApi":  gatewayOutputs["ComplianceApiEndpoint"],
			"RemediationApi": gatewayOutputs["RemediationApiEndpoint"],
			"ResourcesApi":   gatewayOutputs["ResourcesApiEndpoint"],
		})
		wg.Done()
	}()

	// Core
	go func() {
		deployTemplate(awsSession, coreTemplate, sourceBucket, coreStack, map[string]string{
			"AppDomainURL":           bootstrapOutputs["LoadBalancerUrl"],
			"AnalysisVersionsBucket": bootstrapOutputs["AnalysisVersionsBucket"],
			"AnalysisApiId":          gatewayOutputs["AnalysisApiId"],
			"ComplianceApiId":        gatewayOutputs["ComplianceApiId"],
			"SqsKeyId":               bootstrapOutputs["QueueEncryptionKeyId"],
			"UserPoolId":             bootstrapOutputs["UserPoolId"],
			// TODO: optional params from config file
		})
		wg.Done()
	}()

	// Web server
	go func() {
		deployFrontend(awsSession, settings, accountID, sourceBucket, bootstrapOutputs)
		wg.Done()
	}()

	// Athena/Glue
	go func() {
		deployTemplate(awsSession, glueTemplate, sourceBucket, glueStack, map[string]string{
			"ProcessedDataBucket": bootstrapOutputs["ProcessedDataBucket"],
		})

		// Athena views are created via API call because CF is not well supported. Workgroup "primary" is default.
		const workgroup = "primary"
		athenaBucket := bootstrapOutputs["AthenaResultsBucket"]
		if err := awsathena.WorkgroupAssociateS3(awsSession, workgroup, athenaBucket); err != nil {
			logger.Fatalf("failed to associate %s Athena workgroup with %s bucket: %v", workgroup, athenaBucket, err)
		}
		if err := athenaviews.CreateOrReplaceViews(athenaBucket); err != nil {
			logger.Fatalf("failed to create/replace athena views for %s bucket: %v", athenaBucket, err)
		}

		wg.Done()
	}()

	// Monitoring
	go func() {
		deployTemplate(awsSession, monitoringTemplate, sourceBucket, monitoringStack, map[string]string{
			"AlarmTopicArn":        settings.Monitoring.AlarmSnsTopicArn,
			"AppsyncId":            bootstrapOutputs["GraphQLApiId"],
			"LoadBalancerFullName": bootstrapOutputs["LoadBalancerFullName"],
		})
		wg.Done()
	}()

	wg.Wait()
}

// Generate the set of deploy parameters for the main application stack.
//
// This will create a Python layer, pass down the name of the log database,
// pass down user supplied alarm SNS topic and a self-signed cert if necessary.
//func getBackendDeployParams(
//	awsSession *session.Session, settings *config.PantherConfig, sourceBucket string, logBucket string) map[string]string {
//
//	v := settings.BackendParameterValues
//	result := map[string]string{
//		"AuditRoleName":                auditRole,
//		"RemediationRoleName":          remediationRole,
//		"CloudWatchLogRetentionDays":   strconv.Itoa(v.CloudWatchLogRetentionDays),
//		"Debug":                        strconv.FormatBool(v.Debug),
//		"LayerVersionArns":             v.LayerVersionArns,
//		"LogProcessorLambdaMemorySize": strconv.Itoa(v.LogProcessorLambdaMemorySize),
//		"PythonLayerVersionArn":        v.PythonLayerVersionArn,
//		"S3BucketAccessLogs":           logBucket,
//		"S3BucketSource":               sourceBucket,
//		"TracingMode":                  v.TracingMode,
//		"WebApplicationCertificateArn": v.WebApplicationCertificateArn,
//		"CustomDomain":                 v.CustomDomain,
//	}
//
//	// If no custom Python layer is defined, then we need to build the default one.
//	if result["PythonLayerVersionArn"] == "" {
//		result["PythonLayerKey"] = layerS3ObjectKey
//		result["PythonLayerObjectVersion"] = uploadLayer(awsSession, settings.PipLayer, sourceBucket, layerS3ObjectKey)
//	}
//
//	// If no pre-existing cert is provided, then create one if necessary.
//	if result["WebApplicationCertificateArn"] == "" {
//		result["WebApplicationCertificateArn"] = uploadLocalCertificate(awsSession)
//	}
//
//	result["PantherLogProcessingDatabase"] = awsglue.LogProcessingDatabaseName
//
//	return result
//}

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

//// After the main stack is deployed, we need to make several manual API calls
//func postDeploySetup(awsSession *session.Session, backendOutputs map[string]string, settings *config.PantherConfig) error {
//	// Enable software 2FA for the Cognito user pool - this is not yet supported in CloudFormation.
//	userPoolID := backendOutputs["WebApplicationUserPoolId"]
//	logger.Debugf("deploy: enabling TOTP for user pool %s", userPoolID)
//	_, err := cognitoidentityprovider.New(awsSession).SetUserPoolMfaConfig(&cognitoidentityprovider.SetUserPoolMfaConfigInput{
//		MfaConfiguration: aws.String("ON"),
//		SoftwareTokenMfaConfiguration: &cognitoidentityprovider.SoftwareTokenMfaConfigType{
//			Enabled: aws.Bool(true),
//		},
//		UserPoolId: &userPoolID,
//	})
//	if err != nil {
//		return fmt.Errorf("failed to enable TOTP for user pool %s: %v", userPoolID, err)
//	}
//
//	if err := inviteFirstUser(awsSession); err != nil {
//		return err
//	}
//
//	return initializeAnalysisSets(awsSession, backendOutputs["AnalysisApiEndpoint"], settings)
//}
//
//// If the users list is empty (e.g. on the initial deploy), create the first user.
//func inviteFirstUser(awsSession *session.Session) error {
//	input := &usermodels.LambdaInput{
//		ListUsers: &usermodels.ListUsersInput{},
//	}
//	var output usermodels.ListUsersOutput
//	if err := invokeLambda(awsSession, "panther-users-api", input, &output); err != nil {
//		return fmt.Errorf("failed to list users: %v", err)
//	}
//	if len(output.Users) > 0 {
//		return nil
//	}
//
//	// Prompt the user for basic information.
//	logger.Info("setting up initial Panther admin user...")
//	fmt.Println()
//	firstName := promptUser("First name: ", nonemptyValidator)
//	lastName := promptUser("Last name: ", nonemptyValidator)
//	email := promptUser("Email: ", emailValidator)
//	defaultOrgName := firstName + "-" + lastName
//	orgName := promptUser("Company/Team name ("+defaultOrgName+"): ", nil)
//	if orgName == "" {
//		orgName = defaultOrgName
//	}
//
//	// users-api.InviteUser
//	input = &usermodels.LambdaInput{
//		InviteUser: &usermodels.InviteUserInput{
//			GivenName:  &firstName,
//			FamilyName: &lastName,
//			Email:      &email,
//		},
//	}
//	if err := invokeLambda(awsSession, "panther-users-api", input, nil); err != nil {
//		return err
//	}
//	logger.Infof("invite sent to %s: check your email! (it may be in spam)", email)
//
//	// organizations-api.UpdateSettings
//	updateSettingsInput := &orgmodels.LambdaInput{
//		UpdateSettings: &orgmodels.UpdateSettingsInput{DisplayName: &orgName, Email: &email},
//	}
//	return invokeLambda(awsSession, "panther-organization-api", &updateSettingsInput, nil)
//}
//
//// Install Python rules/policies if they don't already exist.
//func initializeAnalysisSets(awsSession *session.Session, endpoint string, settings *config.PantherConfig) error {
//	httpClient := gatewayapi.GatewayClient(awsSession)
//	apiClient := client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
//		WithBasePath("/v1").WithHost(endpoint))
//
//	policies, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
//		PageSize:   aws.Int64(1),
//		HTTPClient: httpClient,
//	})
//	if err != nil {
//		return fmt.Errorf("failed to list existing policies: %v", err)
//	}
//
//	rules, err := apiClient.Operations.ListRules(&operations.ListRulesParams{
//		PageSize:   aws.Int64(1),
//		HTTPClient: httpClient,
//	})
//	if err != nil {
//		return fmt.Errorf("failed to list existing rules: %v", err)
//	}
//
//	if len(policies.Payload.Policies) > 0 || len(rules.Payload.Rules) > 0 {
//		logger.Debug("deploy: initial analysis set ignored: policies and/or rules already exist")
//		return nil
//	}
//
//	var newRules, newPolicies int64
//	for _, path := range settings.InitialAnalysisSets {
//		logger.Info("deploy: uploading initial analysis pack " + path)
//		var contents []byte
//		if strings.HasPrefix(path, "file://") {
//			contents = readFile(strings.TrimPrefix(path, "file://"))
//		} else {
//			contents, err = download(path)
//			if err != nil {
//				return err
//			}
//		}
//
//		// BulkUpload to panther-analysis-api
//		encoded := base64.StdEncoding.EncodeToString(contents)
//		response, err := apiClient.Operations.BulkUpload(&operations.BulkUploadParams{
//			Body: &analysismodels.BulkUpload{
//				Data:   analysismodels.Base64zipfile(encoded),
//				UserID: mageUserID,
//			},
//			HTTPClient: httpClient,
//		})
//		if err != nil {
//			return fmt.Errorf("failed to upload %s: %v", path, err)
//		}
//
//		newRules += *response.Payload.NewRules
//		newPolicies += *response.Payload.NewPolicies
//	}
//
//	logger.Infof("deploy: initialized with %d policies and %d rules", newPolicies, newRules)
//	return nil
//}
