package deploy

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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/pkg"
	"github.com/panther-labs/panther/tools/mage/util"
)

var log = logger.Build("[deploy]")

// SupportedRegions is a set of region names where Panther can be deployed.
// Not all AWS services are available in every region.
// https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services
var SupportedRegions = map[string]bool{
	"ap-northeast-1": true, // tokyo
	"ap-northeast-2": true, // seoul
	"ap-south-1":     true, // mumbai
	"ap-southeast-1": true, // singapore
	"ap-southeast-2": true, // sydney
	"ca-central-1":   true, // canada
	"eu-central-1":   true, // frankfurt
	"eu-north-1":     true, // stockholm
	"eu-west-1":      true, // ireland
	"eu-west-2":      true, // london
	"eu-west-3":      true, // paris
	"sa-east-1":      true, // são paulo
	"us-east-1":      true, // n. virginia
	"us-east-2":      true, // ohio
	"us-west-1":      true, // n. california
	"us-west-2":      true, // oregon
}

// Deploy Panther to your AWS account
func Deploy() error {
	start := time.Now()
	if err := PreCheck(clients.Region()); err != nil {
		return err
	}

	// Deploy 1 or more stacks with STACK="name1 name2" (white space delimited)
	callStackErrors := CallForEachString("STACK", PantherNames(os.Getenv("STACK")), deploySingleStack)

	// Deploy 1 or more lambdas with LAMBDA="name1 name2..." (white space delimited)
	callLambdaErrors := CallForEachString("LAMBDA", PantherNames(os.Getenv("LAMBDA")), deploySingleLambda)

	if len(callStackErrors) > 0 || len(callLambdaErrors) > 0 {
		// Already deployed individual STACKs or LAMBDA functions, skip the full deploy process
		return nil
	}

	log.Infof("deploying Panther %s (%s) to account %s (%s)",
		util.Semver(), util.CommitSha(), clients.AccountID(), clients.Region())

	settings, err := Settings()
	if err != nil {
		return err
	}
	if err = setFirstUser(settings); err != nil {
		return err
	}

	packager, outputs, err := bootstrap(settings)
	if err != nil {
		return err
	}
	if err := deployMainStacks(settings, packager, outputs); err != nil {
		return err
	}

	log.Infof("finished successfully in %s", time.Since(start).Round(time.Second))
	log.Infof("***** Panther URL = https://%s", outputs["LoadBalancerUrl"])
	return nil
}

// Fail the deploy early if there is a known issue with the user's environment.
func PreCheck(region string) error {
	// Ensure the AWS region is supported
	if region != "" && !SupportedRegions[region] {
		return fmt.Errorf("panther is not supported in %s region", region)
	}

	if version := runtime.Version(); version < "go1.15" {
		return fmt.Errorf("go %s not supported, upgrade to 1.15+", version)
	}

	// Make sure docker is running
	if _, err := sh.Output("docker", "info"); err != nil {
		return fmt.Errorf("docker is not available: %v", err)
	}

	// Note: npm and python are not required for deployment
	// (npm install runs within the web dockerfile, need not run locally)

	return nil
}

// Prompt for the name and email of the initial user if not already defined.
func setFirstUser(settings *PantherConfig) error {
	if settings.Setup.FirstUser.Email != "" {
		// Always use the values in the settings file first, if available
		return nil
	}

	input := models.LambdaInput{ListUsers: &models.ListUsersInput{}}
	var output models.ListUsersOutput
	err := genericapi.Invoke(clients.Lambda(), clients.UsersAPI, &input, &output)
	if err != nil && !strings.Contains(err.Error(), lambda.ErrCodeResourceNotFoundException) {
		return fmt.Errorf("failed to list existing users: %v", err)
	}

	if len(output.Users) > 0 {
		// A user already exists - leave the setting blank.
		// This will "delete" the FirstUser custom resource in the web stack, but since that resource
		// has DeletionPolicy:Retain, CloudFormation will ignore it.
		return nil
	}

	// If there is no setting and no existing user, we have to prompt.
	fmt.Println("Who will be the initial Panther admin user?")
	firstName := prompt.Read("First name: ", prompt.NonemptyValidator)
	lastName := prompt.Read("Last name: ", prompt.NonemptyValidator)
	email := prompt.Read("Email: ", prompt.EmailValidator)
	settings.Setup.FirstUser = FirstUser{
		GivenName:  firstName,
		FamilyName: lastName,
		Email:      email,
	}
	return nil
}

// Update a single Lambda function for rapid developer iteration.
//
// This will only update the Lambda source, not the function configuration.
func deploySingleLambda(function string) error {
	// Find the function source path and language from the CFN templates
	type cfnResource struct {
		Type       string
		Properties map[string]interface{}
	}

	type cfnTemplate struct {
		Resources map[string]cfnResource
	}

	for _, path := range []string{
		cfnstacks.LogAnalysisTemplate,
		cfnstacks.CloudsecTemplate,
		cfnstacks.CoreTemplate,
		cfnstacks.GatewayTemplate,
	} {
		var template cfnTemplate
		if err := util.ParseTemplate(path, &template); err != nil {
			return err
		}

		for _, resource := range template.Resources {
			if resource.Type != "AWS::Serverless::Function" {
				continue
			}

			if resource.Properties["FunctionName"].(string) == function {
				return updateLambdaCode(
					function,
					filepath.Join("deployments", resource.Properties["CodeUri"].(string)),
					resource.Properties["Runtime"].(string),
				)
			}
		}
	}

	// Couldn't find the lambda function in any of the templates
	return fmt.Errorf("unknown function LAMBDA=%s", function)
}

func updateLambdaCode(function, srcPath, runtime string) error {
	var pathToZip string

	if strings.HasPrefix(runtime, "go") {
		log.Infof("compiling %s", srcPath)
		binary, err := build.LambdaPackage(srcPath)
		if err != nil {
			return err
		}
		pathToZip = filepath.Dir(binary)
	} else if strings.HasPrefix(runtime, "python") {
		pathToZip = srcPath
	} else {
		return fmt.Errorf("unknown Lambda runtime %s", runtime)
	}

	// Create zipfile
	lambdaZip := filepath.Join("out", "deployments", function+".zip")
	if err := shutil.ZipDirectory(pathToZip, lambdaZip, false); err != nil {
		return fmt.Errorf("failed to zip %s into %s: %v", pathToZip, lambdaZip, err)
	}

	// Update function
	log.Infof("updating code for %s Lambda function %s", runtime, function)
	response, err := clients.Lambda().UpdateFunctionCode(&lambda.UpdateFunctionCodeInput{
		FunctionName: &function,
		ZipFile:      util.MustReadFile(lambdaZip),
	})
	log.Debugf("Lambda update response: %v", response)
	return err
}

// Deploy a single stack for rapid developer iteration.
//
// Can only be used to update an existing deployment.
func deploySingleStack(stack string) error {
	settings, err := Settings()
	if err != nil {
		return err
	}

	var outputs map[string]string
	var packager *pkg.Packager
	if stack != cfnstacks.Bootstrap {
		outputs, err = awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap, cfnstacks.Gateway)
		if err != nil {
			return err
		}
		packager, err = buildPackager(settings, outputs)
		if err != nil {
			return err
		}
	}

	switch stack {
	case cfnstacks.Bootstrap:
		_, err := deployBootstrapStack(settings)
		return err
	case cfnstacks.Gateway:
		_, err := deployBootstrapGatewayStack(settings, packager, outputs)
		return err
	case cfnstacks.Appsync:
		return deployAppsyncStack(packager, outputs)
	case cfnstacks.Cloudsec:
		return deployCloudSecurityStack(settings, packager, outputs)
	case cfnstacks.Core:
		return deployCoreStack(settings, packager, outputs)
	case cfnstacks.Dashboard:
		return deployDashboardStack(packager)
	case cfnstacks.Frontend:
		if err := setFirstUser(settings); err != nil {
			return err
		}
		return deployFrontend(settings, packager, outputs)
	case cfnstacks.LogAnalysis:
		return deployLogAnalysisStack(settings, packager, outputs)
	case cfnstacks.Onboard:
		return deployOnboardStack(settings, packager, outputs)
	default:
		return fmt.Errorf("unknown stack '%s'", stack)
	}
}

func buildPackager(settings *PantherConfig, outputs map[string]string) (*pkg.Packager, error) {
	awsCfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	return &pkg.Packager{
		Log:            log,
		AwsConfig:      awsCfg,
		Bucket:         outputs["SourceBucket"],
		EcrRegistry:    outputs["ImageRegistryUri"],
		EcrTagWithHash: true,
		PipLibs:        settings.Infra.PipLayer,
	}, nil
}

// Deploy bootstrap stacks and build deployment artifacts.
//
// Returns asset packager and combined outputs from bootstrap stacks.
func bootstrap(settings *PantherConfig) (*pkg.Packager, map[string]string, error) {
	outputs, err := deployBootstrapStack(settings)
	if err != nil {
		return nil, nil, err
	}
	log.Infof("    √ %s finished (1/%d)", cfnstacks.Bootstrap, cfnstacks.NumStacks)

	packager, err := buildPackager(settings, outputs)
	if err != nil {
		return nil, nil, err
	}

	// Deploy second bootstrap stack and merge outputs
	gatewayOutputs, err := deployBootstrapGatewayStack(settings, packager, outputs)
	if err != nil {
		return packager, nil, err
	}

	for k, v := range gatewayOutputs {
		if _, exists := outputs[k]; exists {
			return packager, nil, fmt.Errorf("output %s exists in both bootstrap stacks", k)
		}
		outputs[k] = v
	}

	log.Infof("    √ %s finished (2/%d)", cfnstacks.Gateway, cfnstacks.NumStacks)
	return packager, outputs, nil
}

// Deploy main stacks (everything after bootstrap and bootstrap-gateway)
func deployMainStacks(settings *PantherConfig, packager *pkg.Packager, outputs map[string]string) error {
	results := make(chan util.TaskResult)
	completedStackCount := 3 // There are two stacks before this function call
	count := 0

	// Appsync
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Appsync, Err: deployAppsyncStack(packager, outputs)}
	}(results)

	// Cloud security
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Cloudsec, Err: deployCloudSecurityStack(settings, packager, outputs)}
	}(results)

	// Core
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Core, Err: deployCoreStack(settings, packager, outputs)}
	}(results)

	// Dashboards
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Dashboard, Err: deployDashboardStack(packager)}
	}(results)

	// Wait for above stacks to finish.
	if err := util.WaitForTasks(log, results, completedStackCount, count+completedStackCount-1, cfnstacks.NumStacks); err != nil {
		return err
	}

	// next set of stacks
	completedStackCount += count
	count = 0 // reset

	// Log analysis (requires core stack to exist first)
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.LogAnalysis, Err: deployLogAnalysisStack(settings, packager, outputs)}
	}(results)

	// Web stack (requires core stack to exist first)
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Frontend, Err: deployFrontend(settings, packager, outputs)}
	}(results)

	// Wait,  counting where the last parallel group left off to give the illusion of one continuous deploy progress tracker.
	if err := util.WaitForTasks(log, results, completedStackCount, count+completedStackCount-1, cfnstacks.NumStacks); err != nil {
		return err
	}

	// next set of stacks (last)
	completedStackCount += count

	// Onboard Panther to scan itself (requires all stacks deployed)
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Onboard, Err: deployOnboardStack(settings, packager, outputs)}
	}(results)

	// Wait,  counting where the last parallel group left off to give the illusion of one continuous deploy progress tracker.
	return util.WaitForTasks(log, results, completedStackCount, cfnstacks.NumStacks, cfnstacks.NumStacks)
}

func deployBootstrapStack(settings *PantherConfig) (map[string]string, error) {
	// Hack: we still need to "package" the bootstrap template to strip comments
	// so the size is small enough to upload it directly to S3.
	// But the packager won't actually have a bucket configured and won't need to talk to S3.
	packager, err := buildPackager(settings, make(map[string]string))
	if err != nil {
		return nil, err
	}

	return Stack(packager, cfnstacks.BootstrapTemplate, cfnstacks.Bootstrap, map[string]string{
		"AccessLogsBucket":              settings.Setup.S3AccessLogsBucket,
		"AlarmTopicArn":                 settings.Monitoring.AlarmSnsTopicArn,
		"CloudWatchLogRetentionDays":    strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomDomain":                  settings.Web.CustomDomain,
		"DataReplicationBucket":         settings.Setup.DataReplicationBucket,
		"Debug":                         strconv.FormatBool(settings.Monitoring.Debug),
		"DeployFromSource":              "true",
		"EnableS3AccessLogs":            strconv.FormatBool(settings.Setup.EnableS3AccessLogs),
		"LoadBalancerSecurityGroupCidr": settings.Infra.LoadBalancerSecurityGroupCidr,
		"LogSubscriptionPrincipals":     strings.Join(settings.Setup.LogSubscriptions.PrincipalARNs, ","),
		"SecurityGroupID":               settings.Infra.SecurityGroupID,
		"SubnetOneID":                   settings.Infra.SubnetOneID,
		"SubnetTwoID":                   settings.Infra.SubnetTwoID,
		"SubnetOneIPRange":              settings.Infra.SubnetOneIPRange,
		"SubnetTwoIPRange":              settings.Infra.SubnetTwoIPRange,
		"TracingMode":                   settings.Monitoring.TracingMode,
		"VpcID":                         settings.Infra.VpcID,
	})
}

func deployBootstrapGatewayStack(
	settings *PantherConfig,
	packager *pkg.Packager,
	outputs map[string]string, // from bootstrap stack
) (map[string]string, error) {

	return Stack(packager, cfnstacks.GatewayTemplate, cfnstacks.Gateway, map[string]string{
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
		"AthenaResultsBucket":        outputs["AthenaResultsBucket"],
		"AuditLogsBucket":            outputs["AuditLogsBucket"],
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CompanyDisplayName":         settings.Setup.Company.DisplayName,
		"CustomResourceVersion":      customResourceVersion(),
		"ImageRegistryName":          outputs["ImageRegistryName"],
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"ProcessedDataBucket":        outputs["ProcessedDataBucket"],
		"PythonLayerVersionArn":      settings.Infra.PythonLayerVersionArn,
		"SqsKeyId":                   outputs["QueueEncryptionKeyId"],
		"TracingMode":                settings.Monitoring.TracingMode,
		"UserPoolId":                 outputs["UserPoolId"],
	})
}

func deployAppsyncStack(packager *pkg.Packager, outputs map[string]string) error {
	_, err := Stack(packager, cfnstacks.AppsyncTemplate, cfnstacks.Appsync, map[string]string{
		"AlarmTopicArn":         outputs["AlarmTopicArn"],
		"ApiId":                 outputs["GraphQLApiId"],
		"CustomResourceVersion": customResourceVersion(),
		"ServiceRole":           outputs["AppsyncServiceRoleArn"],
	})
	return err
}

func deployCloudSecurityStack(settings *PantherConfig, packager *pkg.Packager, outputs map[string]string) error {
	_, err := Stack(packager, cfnstacks.CloudsecTemplate, cfnstacks.Cloudsec, map[string]string{
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomResourceVersion":      customResourceVersion(),
		"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
		"DynamoScalingRoleArn":       outputs["DynamoScalingRoleArn"],
		"InputDataBucket":            outputs["InputDataBucket"],
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"ProcessedDataBucket":        outputs["ProcessedDataBucket"],
		"ProcessedDataTopicArn":      outputs["ProcessedDataTopicArn"],
		"PythonLayerVersionArn":      outputs["PythonLayerVersionArn"],
		"SqsKeyId":                   outputs["QueueEncryptionKeyId"],
		"TracingMode":                settings.Monitoring.TracingMode,

		// These settings are not supported for source code deploys
		"CloudSecurityMaxReadCapacity":  "0",
		"CloudSecurityMaxWriteCapacity": "0",
		"CloudSecurityMemory":           "512",
		"CloudSecurityMinReadCapacity":  "0",
		"CloudSecurityMinWriteCapacity": "0",
	})
	return err
}

func deployCoreStack(settings *PantherConfig, packager *pkg.Packager, outputs map[string]string) error {
	_, err := Stack(packager, cfnstacks.CoreTemplate, cfnstacks.Core, map[string]string{
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
		"AnalysisVersionsBucket":     outputs["AnalysisVersionsBucket"],
		"AppDomainURL":               outputs["LoadBalancerUrl"],
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CompanyDisplayName":         settings.Setup.Company.DisplayName,
		"CompanyEmail":               settings.Setup.Company.Email,
		"CustomResourceVersion":      customResourceVersion(),
		"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
		"DynamoScalingRoleArn":       outputs["DynamoScalingRoleArn"],
		"InputDataBucket":            outputs["InputDataBucket"],
		"InputDataTopicArn":          outputs["InputDataTopicArn"],
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"OutputsKeyId":               outputs["OutputsEncryptionKeyId"],
		"PantherVersion":             util.Semver(),
		"KvTableBillingMode":         settings.Infra.KvTableBillingMode,
		"SqsKeyId":                   outputs["QueueEncryptionKeyId"],
		"TracingMode":                settings.Monitoring.TracingMode,
		"UserPoolId":                 outputs["UserPoolId"],
	})
	return err
}

func deployDashboardStack(packager *pkg.Packager) error {
	_, err := Stack(packager, cfnstacks.DashboardTemplate, cfnstacks.Dashboard, nil)
	return err
}

func deployLogAnalysisStack(settings *PantherConfig, packager *pkg.Packager, outputs map[string]string) error {
	_, err := Stack(packager, cfnstacks.LogAnalysisTemplate, cfnstacks.LogAnalysis, map[string]string{
		"AlarmTopicArn":                      outputs["AlarmTopicArn"],
		"AthenaResultsBucket":                outputs["AthenaResultsBucket"],
		"AthenaWorkGroup":                    outputs["AthenaWorkGroup"],
		"CloudWatchLogRetentionDays":         strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomResourceVersion":              customResourceVersion(),
		"Debug":                              strconv.FormatBool(settings.Monitoring.Debug),
		"InputDataBucket":                    outputs["InputDataBucket"],
		"InputDataTopicArn":                  outputs["InputDataTopicArn"],
		"LayerVersionArns":                   settings.Infra.BaseLayerVersionArns,
		"LogProcessorLambdaMemorySize":       strconv.Itoa(settings.Infra.LogProcessorLambdaMemorySize),
		"LogProcessorLambdaSQSReadBatchSize": settings.Infra.LogProcessorLambdaSQSReadBatchSize,
		"ProcessedDataBucket":                outputs["ProcessedDataBucket"],
		"ProcessedDataTopicArn":              outputs["ProcessedDataTopicArn"],
		"PythonLayerVersionArn":              outputs["PythonLayerVersionArn"],
		"SqsKeyId":                           outputs["QueueEncryptionKeyId"],
		"TracingMode":                        settings.Monitoring.TracingMode,
	})
	return err
}

func deployOnboardStack(settings *PantherConfig, packager *pkg.Packager, outputs map[string]string) error {
	var err error
	if settings.Setup.OnboardSelf {
		_, err = Stack(packager, cfnstacks.OnboardTemplate, cfnstacks.Onboard, map[string]string{
			"AlarmTopicArn":         outputs["AlarmTopicArn"],
			"AuditLogsBucket":       outputs["AuditLogsBucket"],
			"CustomResourceVersion": customResourceVersion(),
			"EnableCloudTrail":      strconv.FormatBool(settings.Setup.EnableCloudTrail),
			"EnableGuardDuty":       strconv.FormatBool(settings.Setup.EnableGuardDuty),
			"EnableS3AccessLogs":    strconv.FormatBool(settings.Setup.EnableS3AccessLogs),
		})
	} else {
		// Delete the onboard stack if OnboardSelf was toggled off
		err = awscfn.DeleteStack(clients.Cfn(), log, cfnstacks.Onboard, pollInterval)
	}

	return err
}

// Determine the custom resource "version" - if this value changes, it will force an update for
// most of our CloudFormation custom resources.
func customResourceVersion() string {
	if v := os.Getenv("CUSTOM_RESOURCE_VERSION"); v != "" {
		return v
	}

	// This is the same format as the version shown in the general settings page,
	// and also the same format used by the master stack.
	return fmt.Sprintf("%s (%s)", util.Semver(), util.CommitSha())
}

// Takes a string  and returns the panther- prefixed, lowercased slice of words(strings) (separated by spaces).
// e.g "oRg-ApI" -> []string{"panther-org-api"}
// e.g "one two THREE" -> []string{"panther-one", "panther-two", "panther-three"}
func PantherNames(setString string) []string {
	set := strings.Fields(setString)
	for i, entry := range set {
		entry = strings.ToLower(entry)
		if !strings.HasPrefix(entry, "panther-") {
			entry = "panther-" + entry
		}
		set[i] = entry
	}
	return set
}

// Call a method for every string in the callOnSet string slice. Return a slice of errors where the
// index of the error is the index of the callOnSet string used as the argument in the function call.
func CallForEachString(label string, callOnSet []string, callFn func(string) error) (callErrors []error) {
	for _, setEntry := range callOnSet {
		log.Infof("%s: %v", label, setEntry)
		err := callFn(setEntry)
		if err != nil {
			log.Errorf("%s: %s %v", label, setEntry, err)
		}
		callErrors = append(callErrors, err)
	}
	return callErrors
}
