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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/fatih/color"
	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	orgmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	usermodels "github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/athenaviews"
)

const (
	// CloudFormation templates + stacks
	backendStack    = "panther-app"
	backendTemplate = "deployments/backend.yml"
	bucketStack     = "panther-buckets" // prereq stack with Panther S3 buckets
	bucketTemplate  = "deployments/core/buckets.yml"

	// Python layer
	layerSourceDir   = "out/pip/analysis/python"
	layerZipfile     = "out/layer.zip"
	layerS3ObjectKey = "layers/python-analysis.zip"
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
	var config PantherConfig
	if err := yaml.Unmarshal(readFile(configFile), &config); err != nil {
		logger.Fatalf("failed to parse config file %s: %v", configFile, err)
	}

	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}

	deployPrecheck(aws.StringValue(awsSession.Config.Region))
	Build.Lambda(Build{})
	preprocessTemplates()

	// Deploy prerequisite bucket stack
	bucketParams := map[string]string{
		"AccessLogsBucketName": config.BucketsParameterValues.AccessLogsBucketName,
	}
	bucketOutputs := deployTemplate(awsSession, bucketTemplate, "", bucketStack, bucketParams)
	bucket := bucketOutputs["SourceBucketName"]

	// Deploy main application stack
	params := getBackendDeployParams(awsSession, &config, bucket)
	backendOutputs := deployTemplate(awsSession, backendTemplate, bucket, backendStack, params)
	if err := postDeploySetup(awsSession, backendOutputs, &config); err != nil {
		logger.Fatal(err)
	}

	// Deploy frontend stack
	deployFrontend(awsSession, bucket, backendOutputs, &config)

	// Done!
	logger.Infof("deploy: finished successfully in %s", time.Since(start))
	color.Yellow("\nPanther URL = https://%s\n", backendOutputs["LoadBalancerUrl"])
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

	// Ensure swagger is installed
	swagger := filepath.Join(setupDirectory, "swagger")
	if _, err := os.Stat(swagger); err != nil {
		logger.Fatalf("%s not found (%v): run 'mage setup:all'", swagger, err)
	}
}

// Generate the set of deploy parameters for the main application stack.
//
// This will create a Python layer and a self-signed cert if necessary.
func getBackendDeployParams(awsSession *session.Session, config *PantherConfig, bucket string) map[string]string {
	v := config.BackendParameterValues
	result := map[string]string{
		"CloudWatchLogRetentionDays":   strconv.Itoa(v.CloudWatchLogRetentionDays),
		"Debug":                        strconv.FormatBool(v.Debug),
		"LayerVersionArns":             v.LayerVersionArns,
		"PythonLayerVersionArn":        v.PythonLayerVersionArn,
		"WebApplicationCertificateArn": v.WebApplicationCertificateArn,
		"TracingMode":                  v.TracingMode,
	}

	// If no custom Python layer is defined, then we need to build the default one.
	if result["PythonLayerVersionArn"] == "" {
		result["PythonLayerKey"] = layerS3ObjectKey
		result["PythonLayerObjectVersion"] = uploadLayer(awsSession, config.PipLayer, bucket, layerS3ObjectKey)
	}

	// If no pre-existing cert is provided, then create one if necessary.
	if result["WebApplicationCertificateArn"] == "" {
		result["WebApplicationCertificateArn"] = uploadLocalCertificate(awsSession)
	}

	return result
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

// After the main stack is deployed, we need to make several manual API calls
func postDeploySetup(awsSession *session.Session, backendOutputs map[string]string, config *PantherConfig) error {
	// Athena views are created via API call because CF is not well supported. Workgroup "primary" is default.
	workgroup, bucket := "primary", backendOutputs["AthenaResultsBucket"]
	if err := awsathena.WorkgroupAssociateS3(awsSession, workgroup, bucket); err != nil {
		return fmt.Errorf("failed to associate %s Athena workgroup with %s bucket: %v", workgroup, bucket, err)
	}
	if err := athenaviews.CreateOrReplaceViews(bucket); err != nil {
		return fmt.Errorf("failed to create/replace athena views for %s bucket: %v", bucket, err)
	}

	// Enable software 2FA for the Cognito user pool - this is not yet supported in CloudFormation.
	userPoolID := backendOutputs["WebApplicationUserPoolId"]
	logger.Debugf("deploy: enabling TOTP for user pool %s", userPoolID)
	_, err := cognitoidentityprovider.New(awsSession).SetUserPoolMfaConfig(&cognitoidentityprovider.SetUserPoolMfaConfigInput{
		MfaConfiguration: aws.String("ON"),
		SoftwareTokenMfaConfiguration: &cognitoidentityprovider.SoftwareTokenMfaConfigType{
			Enabled: aws.Bool(true),
		},
		UserPoolId: &userPoolID,
	})
	if err != nil {
		return fmt.Errorf("failed to enable TOTP for user pool %s: %v", userPoolID, err)
	}

	if err := setupOrganization(awsSession, backendOutputs["WebApplicationUserPoolId"]); err != nil {
		return err
	}

	return initializeAnalysisSets(awsSession, backendOutputs["AnalysisApiEndpoint"], config)
}

// If the Admin group is empty (e.g. on the initial deploy), create the initial admin user and organization
func setupOrganization(awsSession *session.Session, userPoolID string) error {
	cognitoClient := cognitoidentityprovider.New(awsSession)
	group, err := cognitoClient.ListUsersInGroup(&cognitoidentityprovider.ListUsersInGroupInput{
		GroupName:  aws.String("Admin"),
		UserPoolId: &userPoolID,
	})
	if err != nil {
		return fmt.Errorf("failed to list Admin users in Cognito user pool %s: %v", userPoolID, err)
	}
	if len(group.Users) > 0 {
		return nil // an admin already exists - nothing to do
	}

	// Prompt the user for email + first/last name
	logger.Info("setting up initial Panther admin user...")
	fmt.Println()
	firstName := promptUser("First name: ", nonemptyValidator)
	lastName := promptUser("Last name: ", nonemptyValidator)
	email := promptUser("Email: ", emailValidator)

	// Hit users-api.InviteUser to invite a new user to the admin group
	input := &usermodels.LambdaInput{
		InviteUser: &usermodels.InviteUserInput{
			GivenName:  &firstName,
			FamilyName: &lastName,
			Email:      &email,
			UserPoolID: &userPoolID,
		},
	}
	if err := invokeLambda(awsSession, "panther-users-api", input); err != nil {
		return err
	}
	logger.Infof("invite sent to %s: check your email! (it may be in spam)", email)

	// Hit organization-api.CreateOrganization to create organization entry
	createOrgInput := &orgmodels.LambdaInput{
		CreateOrganization: &orgmodels.CreateOrganizationInput{
			Email:       &email,
			DisplayName: aws.String(firstName + "-" + lastName),
		},
	}
	return invokeLambda(awsSession, "panther-organization-api", createOrgInput)
}

// Install Python rules/policies if they don't already exist.
func initializeAnalysisSets(awsSession *session.Session, endpoint string, config *PantherConfig) error {
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
	for _, path := range config.InitialAnalysisSets {
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
				UserID: "00000000-0000-0000-0000-000000000000",
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
