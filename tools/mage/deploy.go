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
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/fatih/color"
	jsoniter "github.com/json-iterator/go"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	orgmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/shutil"
)

const (
	// CloudFormation templates + stacks
	backendStack     = "panther-app"
	backendTemplate  = "deployments/backend.yml"
	frontendStack    = "panther-app-frontend"
	frontendTemplate = "deployments/frontend.yml"
	bucketStack      = "panther-buckets" // prereq stack with Panther S3 buckets
	bucketTemplate   = "deployments/core/buckets.yml"

	// Python layer
	layerSourceDir   = "out/pip/analysis/python"
	layerZipfile     = "out/layer.zip"
	layerS3ObjectKey = "layers/python-analysis.zip"
)

// NOTE: Mage ignores the first word of the comment if it matches the function name.
// So the comment below is intentionally "Deploy Deploy"

// Deploy Deploy application infrastructure
func Deploy() error {
	var config PantherConfig
	if err := loadYamlFile(configFile, &config); err != nil {
		return err
	}

	awsSession, err := session.NewSession()
	if err != nil {
		return err
	}

	bucketParams := map[string]string{
		"AccessLogsBucketName": config.BucketsParameterValues.AccessLogsBucketName,
	}
	if err = deployTemplate(awsSession, bucketTemplate, bucketStack, bucketParams); err != nil {
		return err
	}

	if err = Build.Lambda(Build{}); err != nil {
		return err
	}

	if err = generateGlueTables(); err != nil {
		return err
	}

	if err = embedAPISpecs(); err != nil {
		return err
	}

	bucketOutputs, err := getStackOutputs(awsSession, bucketStack)
	if err != nil {
		return err
	}
	bucket := bucketOutputs["SourceBucketName"]

	backendTemplate, err := cfnPackage(backendTemplate, bucket, backendStack)
	if err != nil {
		return err
	}

	backendDeployParams, err := getBackendDeployParams(awsSession, &config, bucket)
	if err != nil {
		return err
	}

	if err = deployTemplate(awsSession, backendTemplate, backendStack, backendDeployParams); err != nil {
		return err
	}

	backendOutputs, err := getStackOutputs(awsSession, backendStack)
	if err != nil {
		return err
	}

	if err := generateDotEnvFromCfnOutputs(awsSession, backendOutputs, "out/.env"); err != nil {
		return err
	}

	dockerImage, err := buildAndPushImageFromSource(awsSession, backendOutputs["WebApplicationImageRegistry"])
	if err != nil {
		return err
	}

	frontendTemplate, err := cfnPackage(frontendTemplate, bucket, frontendStack)
	if err != nil {
		return err
	}

	frontendDeployParams := getFrontendDeployParams(&config, dockerImage, backendOutputs)

	if err = deployTemplate(awsSession, frontendTemplate, frontendStack, frontendDeployParams); err != nil {
		return err
	}

	if err := enableTOTP(awsSession, backendOutputs["WebApplicationUserPoolId"]); err != nil {
		return err
	}

	if err := setupOrganization(awsSession, backendOutputs["WebApplicationUserPoolId"]); err != nil {
		return err
	}

	if err := initializeAnalysisSets(awsSession, backendOutputs["AnalysisApiEndpoint"], &config); err != nil {
		return err
	}

	color.Yellow("\nPanther URL = https://%s\n", backendOutputs["LoadBalancerUrl"])
	return nil
}

// Generate the set of deploy parameters for the main application stack.
//
// This will first upload the layer zipfile unless a custom layer is specified.
func getBackendDeployParams(awsSession *session.Session, config *PantherConfig, bucket string) (map[string]string, error) {
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
		version, err := uploadLayer(awsSession, config.PipLayer, bucket, layerS3ObjectKey)
		if err != nil {
			return nil, err
		}
		result["PythonLayerKey"] = layerS3ObjectKey
		result["PythonLayerObjectVersion"] = version
	}

	if result["WebApplicationCertificateArn"] == "" {
		certificateArn, err := uploadLocalCertificate(awsSession)
		if err != nil {
			return nil, err
		}
		result["WebApplicationCertificateArn"] = certificateArn
	}

	return result, nil
}

func getFrontendDeployParams(config *PantherConfig, image string, backendOutputs map[string]string) map[string]string {
	frontend := config.FrontendParameterValues
	result := map[string]string{
		"WebApplicationFargateTaskCPU":              strconv.Itoa(frontend.WebApplicationFargateTaskCPU),
		"WebApplicationFargateTaskMemory":           strconv.Itoa(frontend.WebApplicationFargateTaskMemory),
		"WebApplicationImage":                       image,
		"WebApplicationClusterName":                 backendOutputs["WebApplicationClusterName"],
		"WebApplicationVpcId":                       backendOutputs["WebApplicationVpcId"],
		"WebApplicationSubnetOneId":                 backendOutputs["WebApplicationSubnetOneId"],
		"WebApplicationSubnetTwoId":                 backendOutputs["WebApplicationSubnetTwoId"],
		"WebApplicationLoadBalancerListenerArn":     backendOutputs["WebApplicationLoadBalancerListenerArn"],
		"WebApplicationLoadBalancerSecurityGroupId": backendOutputs["WebApplicationLoadBalancerSecurityGroupId"],
	}

	return result
}

// Upload custom Python analysis layer to S3 (if it isn't already), returning version ID
func uploadLayer(awsSession *session.Session, libs []string, bucket, key string) (string, error) {
	s3Client := s3.New(awsSession)
	head, err := s3Client.HeadObject(&s3.HeadObjectInput{Bucket: &bucket, Key: &key})

	sort.Strings(libs)
	libString := strings.Join(libs, ",")
	if err == nil && aws.StringValue(head.Metadata["Libs"]) == libString {
		fmt.Printf("deploy: s3://%s/%s exists and is up to date\n", bucket, key)
		return *head.VersionId, nil
	}

	// The layer is re-uploaded only if it doesn't exist yet or the library versions changed.
	fmt.Println("deploy: downloading " + libString)
	if err := os.RemoveAll(layerSourceDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(layerSourceDir, 0755); err != nil {
		return "", err
	}
	args := append([]string{"install", "-t", layerSourceDir}, libs...)
	if err := sh.Run("pip3", args...); err != nil {
		return "", err
	}

	// The package structure needs to be:
	//
	// layer.zip
	// │ python/policyuniverse/
	// └ python/policyuniverse-VERSION.dist-info/
	//
	// https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path
	if err := shutil.ZipDirectory(path.Dir(layerSourceDir), layerZipfile); err != nil {
		return "", err
	}

	// Upload to S3
	result, err := uploadFileToS3(awsSession, layerZipfile, bucket, key, map[string]*string{"Libs": &libString})
	if err != nil {
		return "", err
	}
	return *result.VersionID, nil
}

// Upload resources to S3 and return the path to the modified CloudFormation template.
// TODO - replace this with our own to avoid relying on the aws cli
func cfnPackage(templateFile, bucket, stack string) (string, error) {
	outputDir := path.Join("out", path.Dir(templateFile))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}

	// There is no equivalent to this command in the AWS Go SDK.
	pkgOut := path.Join(outputDir, "package."+path.Base(templateFile))
	args := []string{"cloudformation", "package",
		"--output-template-file", pkgOut,
		"--s3-bucket", bucket,
		"--s3-prefix", stack,
		"--template-file", templateFile,
	}

	if mg.Verbose() {
		return pkgOut, sh.Run("aws", args...)
	}

	// By default, just print a single progress message instead of several lines of explanation
	fmt.Printf("deploy: cloudformation package %s => %s\n", templateFile, pkgOut)
	_, err := sh.Output("aws", args...)
	return pkgOut, err
}

// Enable software 2FA for the Cognito user pool - this is not yet supported in CloudFormation.
func enableTOTP(awsSession *session.Session, userPoolID string) error {
	if mg.Verbose() {
		fmt.Printf("deploy: enabling TOTP for user pool %s\n", userPoolID)
	}

	client := cognitoidentityprovider.New(awsSession)
	_, err := client.SetUserPoolMfaConfig(&cognitoidentityprovider.SetUserPoolMfaConfigInput{
		MfaConfiguration: aws.String("ON"),
		SoftwareTokenMfaConfiguration: &cognitoidentityprovider.SoftwareTokenMfaConfigType{
			Enabled: aws.Bool(true),
		},
		UserPoolId: &userPoolID,
	})
	return err
}

// If the Admin group is empty (e.g. on the initial deploy), create the initial admin user and organization
func setupOrganization(awsSession *session.Session, userPoolID string) error {
	cognitoClient := cognitoidentityprovider.New(awsSession)
	group, err := cognitoClient.ListUsersInGroup(&cognitoidentityprovider.ListUsersInGroupInput{
		GroupName:  aws.String("Admin"),
		UserPoolId: &userPoolID,
	})
	if err != nil {
		return err
	}
	if len(group.Users) > 0 {
		return nil // an admin already exists - nothing to do
	}

	// Prompt the user for email + first/last name
	fmt.Println("\nSetting up initial Panther admin user...")
	firstName := promptUser("First name: ", nonemptyValidator)
	lastName := promptUser("Last name: ", nonemptyValidator)
	email := promptUser("Email: ", emailValidator)

	// Hit users-api.InviteUser to invite a new user to the admin group
	input := &models.LambdaInput{
		InviteUser: &models.InviteUserInput{
			GivenName:  &firstName,
			FamilyName: &lastName,
			Email:      &email,
			UserPoolID: &userPoolID,
			Role:       aws.String("Admin"),
		},
	}
	if err := invokeLambda(awsSession, "panther-users-api", input); err != nil {
		return err
	}

	// Hit organization-api.CreateOrganization to create organization entry
	createOrgInput := &orgmodels.LambdaInput{
		CreateOrganization: &orgmodels.CreateOrganizationInput{
			Email:       &email,
			DisplayName: aws.String(firstName + "-" + lastName),
		},
	}
	if err := invokeLambda(awsSession, "panther-organization-api", createOrgInput); err != nil {
		return err
	}
	return nil
}

func invokeLambda(awsSession *session.Session, functionName string, input interface{}) error {
	payload, err := jsoniter.Marshal(input)
	if err != nil {
		return err
	}

	lambdaClient := lambda.New(awsSession)
	response, err := lambdaClient.Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(functionName),
		Payload:      payload,
	})
	if err != nil {
		return err
	}

	if response.FunctionError != nil {
		return fmt.Errorf("failed to invoke %s: %s error: %s",
			functionName, *response.FunctionError, string(response.Payload))
	}
	return nil
}
