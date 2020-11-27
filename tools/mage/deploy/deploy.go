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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

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
	if err := PreCheck(); err != nil {
		return err
	}

	if function := os.Getenv("LAMBDA"); function != "" {
		function = strings.ToLower(strings.TrimSpace(function))
		if !strings.HasPrefix(function, "panther-") {
			function = "panther-" + function
		}
		return deploySingleLambda(function)
	}

	if stack := os.Getenv("STACK"); stack != "" {
		stack = strings.ToLower(strings.TrimSpace(stack))
		if !strings.HasPrefix(stack, "panther-") {
			stack = "panther-" + stack
		}
		return deploySingleStack(stack)
	}

	log.Infof("deploying Panther %s to account %s (%s)",
		util.RepoVersion(), clients.AccountID(), clients.Region())

	settings, err := Settings()
	if err != nil {
		return err
	}
	if err = setFirstUser(settings); err != nil {
		return err
	}

	outputs, err := bootstrap(settings)
	if err != nil {
		return err
	}
	if err := deployMainStacks(settings, outputs); err != nil {
		return err
	}

	log.Infof("finished successfully in %s", time.Since(start).Round(time.Second))
	log.Infof("***** Panther URL = https://%s", outputs["LoadBalancerUrl"])
	return nil
}

// Fail the deploy early if there is a known issue with the user's environment.
func PreCheck() error {
	// Ensure the AWS region is supported
	if region := clients.Region(); !SupportedRegions[region] {
		return fmt.Errorf("panther is not supported in %s region", region)
	}

	// Check the Go version (1.12 fails with a build error)
	if version := runtime.Version(); version <= "go1.12" {
		return fmt.Errorf("go %s not supported, upgrade to 1.13+", version)
	}

	// Check the major node version
	nodeVersion, err := sh.Output("node", "--version")
	if err != nil {
		return fmt.Errorf("failed to check node version: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(nodeVersion), "v12") {
		return fmt.Errorf("node version must be v12.x.x, found %s", nodeVersion)
	}

	// Make sure docker is running
	if _, err = sh.Output("docker", "info"); err != nil {
		return fmt.Errorf("docker is not available: %v", err)
	}

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
		srcPath = strings.TrimPrefix(srcPath, "out/")
		srcPath = strings.TrimPrefix(srcPath, "bin/")
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
	pkg := filepath.Join("out", "deployments", function+".zip")
	if err := shutil.ZipDirectory(pathToZip, pkg, false); err != nil {
		return fmt.Errorf("failed to zip %s into %s: %v", pathToZip, pkg, err)
	}

	// Update function
	log.Infof("updating code for %s Lambda function %s", runtime, function)
	response, err := clients.Lambda().UpdateFunctionCode(&lambda.UpdateFunctionCodeInput{
		FunctionName: &function,
		ZipFile:      util.MustReadFile(pkg),
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

	switch stack {
	case cfnstacks.Bootstrap:
		_, err := deployBootstrapStack(settings)
		return err
	case cfnstacks.Gateway:
		if err := build.Lambda(); err != nil { // custom-resources
			return err
		}
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap)
		if err != nil {
			return err
		}
		_, err = deployBootstrapGatewayStack(settings, outputs)
		return err
	case cfnstacks.Appsync:
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap, cfnstacks.Gateway)
		if err != nil {
			return err
		}
		return deployAppsyncStack(outputs)
	case cfnstacks.Cloudsec:
		if err := build.Lambda(); err != nil {
			return err
		}
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap, cfnstacks.Gateway)
		if err != nil {
			return err
		}
		return deployCloudSecurityStack(settings, outputs)
	case cfnstacks.Core:
		if err := build.Lambda(); err != nil {
			return err
		}
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap, cfnstacks.Gateway)
		if err != nil {
			return err
		}
		return deployCoreStack(settings, outputs)
	case cfnstacks.Dashboard:
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap)
		if err != nil {
			return err
		}
		return deployDashboardStack(outputs["SourceBucket"])
	case cfnstacks.Frontend:
		if err := setFirstUser(settings); err != nil {
			return err
		}
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap, cfnstacks.Gateway)
		if err != nil {
			return err
		}
		return deployFrontend(outputs, settings)
	case cfnstacks.LogAnalysis:
		if err := build.Lambda(); err != nil {
			return err
		}
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap, cfnstacks.Gateway)
		if err != nil {
			return err
		}
		return deployLogAnalysisStack(settings, outputs)
	case cfnstacks.Onboard:
		outputs, err := awscfn.StackOutputs(clients.Cfn(), cfnstacks.Bootstrap)
		if err != nil {
			return err
		}
		return deployOnboardStack(settings, outputs)
	default:
		return fmt.Errorf("unknown stack '%s'", stack)
	}
}

// Deploy bootstrap stacks and build deployment artifacts.
//
// Returns combined outputs from bootstrap stacks.
func bootstrap(settings *PantherConfig) (map[string]string, error) {
	// Lambda compilation required for most stacks, including bootstrap-gateway
	if err := build.Lambda(); err != nil {
		return nil, err
	}

	outputs, err := deployBootstrapStack(settings)
	if err != nil {
		return nil, err
	}
	log.Infof("    √ %s finished (1/%d)", cfnstacks.Bootstrap, cfnstacks.NumStacks)

	// Deploy second bootstrap stack and merge outputs
	gatewayOutputs, err := deployBootstrapGatewayStack(settings, outputs)
	if err != nil {
		return nil, err
	}

	for k, v := range gatewayOutputs {
		if _, exists := outputs[k]; exists {
			return nil, fmt.Errorf("output %s exists in both bootstrap stacks", k)
		}
		outputs[k] = v
	}

	log.Infof("    √ %s finished (2/%d)", cfnstacks.Gateway, cfnstacks.NumStacks)
	return outputs, nil
}

// Deploy main stacks (everything after bootstrap and bootstrap-gateway)
func deployMainStacks(settings *PantherConfig, outputs map[string]string) error {
	results := make(chan util.TaskResult)
	completedStackCount := 3 // There are two stacks before this function call
	count := 0

	// Appsync
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Appsync, Err: deployAppsyncStack(outputs)}
	}(results)

	// Cloud security
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Cloudsec, Err: deployCloudSecurityStack(settings, outputs)}
	}(results)

	// Core
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Core, Err: deployCoreStack(settings, outputs)}
	}(results)

	// Dashboards
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Dashboard, Err: deployDashboardStack(outputs["SourceBucket"])}
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
		c <- util.TaskResult{Summary: cfnstacks.LogAnalysis, Err: deployLogAnalysisStack(settings, outputs)}
	}(results)

	// Web stack (requires core stack to exist first)
	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Frontend, Err: deployFrontend(outputs, settings)}
	}(results)

	// Wait,  counting where the last parallel group left off to give the illusion of one continuous deploy progress tracker.
	if err := util.WaitForTasks(log, results, completedStackCount, count+completedStackCount-1, cfnstacks.NumStacks); err != nil {
		return err
	}

	// next set of stacks (last)
	completedStackCount += count

	// Onboard Panther to scan itself (requires all stacks deployed)
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: cfnstacks.Onboard, Err: deployOnboardStack(settings, outputs)}
	}(results)

	// Wait,  counting where the last parallel group left off to give the illusion of one continuous deploy progress tracker.
	return util.WaitForTasks(log, results, completedStackCount, cfnstacks.NumStacks, cfnstacks.NumStacks)
}

func deployBootstrapStack(settings *PantherConfig) (map[string]string, error) {
	return deployTemplate(cfnstacks.BootstrapTemplate, "", cfnstacks.Bootstrap, map[string]string{
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
		"SubnetOneIPRange":              settings.Infra.SubnetOneIPRange,
		"SubnetTwoIPRange":              settings.Infra.SubnetTwoIPRange,
		"TracingMode":                   settings.Monitoring.TracingMode,
		"VpcID":                         settings.Infra.VpcID,
	})
}

func deployBootstrapGatewayStack(
	settings *PantherConfig,
	outputs map[string]string, // from bootstrap stack
) (map[string]string, error) {

	if err := build.Layer(log, settings.Infra.PipLayer); err != nil {
		return nil, err
	}

	return deployTemplate(cfnstacks.GatewayTemplate, outputs["SourceBucket"], cfnstacks.Gateway, map[string]string{
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

func deployAppsyncStack(outputs map[string]string) error {
	_, err := deployTemplate(cfnstacks.AppsyncTemplate, outputs["SourceBucket"], cfnstacks.Appsync, map[string]string{
		"AlarmTopicArn":         outputs["AlarmTopicArn"],
		"ApiId":                 outputs["GraphQLApiId"],
		"CustomResourceVersion": customResourceVersion(),
		"ServiceRole":           outputs["AppsyncServiceRoleArn"],
	})
	return err
}

func deployCloudSecurityStack(settings *PantherConfig, outputs map[string]string) error {
	_, err := deployTemplate(cfnstacks.CloudsecTemplate, outputs["SourceBucket"], cfnstacks.Cloudsec, map[string]string{
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomResourceVersion":      customResourceVersion(),
		"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
		"InputDataBucket":            outputs["InputDataBucket"],
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"ProcessedDataBucket":        outputs["ProcessedDataBucket"],
		"ProcessedDataTopicArn":      outputs["ProcessedDataTopicArn"],
		"PythonLayerVersionArn":      outputs["PythonLayerVersionArn"],
		"SqsKeyId":                   outputs["QueueEncryptionKeyId"],
		"TracingMode":                settings.Monitoring.TracingMode,
	})
	return err
}

func deployCoreStack(settings *PantherConfig, outputs map[string]string) error {
	_, err := deployTemplate(cfnstacks.CoreTemplate, outputs["SourceBucket"], cfnstacks.Core, map[string]string{
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
		"SqsKeyId":                   outputs["QueueEncryptionKeyId"],
		"TracingMode":                settings.Monitoring.TracingMode,
		"UserPoolId":                 outputs["UserPoolId"],
	})
	return err
}

func deployDashboardStack(bucket string) error {
	_, err := deployTemplate(cfnstacks.DashboardTemplate, bucket, cfnstacks.Dashboard, nil)
	return err
}

func deployLogAnalysisStack(settings *PantherConfig, outputs map[string]string) error {
	_, err := deployTemplate(cfnstacks.LogAnalysisTemplate, outputs["SourceBucket"], cfnstacks.LogAnalysis, map[string]string{
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

func deployOnboardStack(settings *PantherConfig, outputs map[string]string) error {
	var err error
	if settings.Setup.OnboardSelf {
		_, err = deployTemplate(cfnstacks.OnboardTemplate, outputs["SourceBucket"], cfnstacks.Onboard, map[string]string{
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

	// By default, just use the major release version so developers do not have to trigger every
	// custom resource on every deploy.
	return strings.Split(util.RepoVersion(), "-")[0]
}
