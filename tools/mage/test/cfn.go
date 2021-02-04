package test

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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

var cfnTests = []testTask{
	{"cfn-lint", testCfnLint},
	{"terraform validate", testTfValidate},
}

// A subset of CFN structure we care about when running tests.
type cfnTemplate struct {
	Parameters map[string]cfnParameter
	Resources  map[string]cfnResource
	Outputs    map[string]interface{}
}

type cfnParameter struct {
	Type    string
	Default interface{}
}

type cfnResource struct {
	Type       string
	Properties map[string]interface{}
}

// Lint CloudFormation and Terraform templates
func Cfn() error {
	log = logger.Build("[test:cfn]")
	return runTests(cfnTests)
}

func testCfnLint() error {
	var templates []string
	util.MustWalk("deployments", func(path string, info os.FileInfo) error {
		if !info.IsDir() && filepath.Ext(path) == ".yml" && !strings.HasSuffix(path, "_config.yml") {
			templates = append(templates, path)
		}
		return nil
	})

	// cfn-lint will complain:
	//   E3012 Property Resources/SnapshotDLQ/Properties/MessageRetentionPeriod should be of type Integer
	//
	// But if we keep them integers, yaml marshaling converts large integers to scientific notation,
	// which CFN does not understand. So we force string values to serialize them correctly.
	args := []string{
		"-x", "E3012:strict=false",
		// cfn-lint complains: E3002 Invalid Property Resources/WebApplicationServer/Properties/NetworkConfiguration/AwsvpcConfiguration
		//deployments/web_server.yml:208:9 .
		// nolint:lll
		// However this property is valid: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-networkconfiguration.html#cfn-ecs-service-networkconfiguration-awsvpcconfiguration
		"-i", "E3002",
		"-i", "W3002", // warns about templates which require packaging; ours all do
		"--"}
	args = append(args, templates...)
	if err := sh.RunV(util.PipPath("cfn-lint"), args...); err != nil {
		return err
	}

	// Parse Panther CloudFormation, map template path to parsed body
	parsed := make(map[string]cfnTemplate, cfnstacks.NumStacks+1)
	for _, template := range templates {
		if strings.HasPrefix(template, "deployments/auxiliary") {
			continue
		}

		var body cfnTemplate
		if err := util.ParseTemplate(template, &body); err != nil {
			return fmt.Errorf("failed to parse %s: %v", template, err)
		}
		parsed[template] = body
	}

	// Panther-specific linting for main stacks
	//   - No default parameter values
	//   - Required custom resources
	var errs []string
	for template, body := range parsed {
		if template == "deployments/root.yml" {
			continue
		}

		// Parameter defaults should not be defined in the nested stacks. Defaults are defined in:
		//   - the config file, when deploying from source
		//   - the master template, for pre-packaged deployments
		//
		// Allowing defaults in nested stacks is confusing and leads to bugs where a parameter is
		// defined but never passed through during deployment.
		for name, options := range body.Parameters {
			if options.Default != nil {
				errs = append(errs, fmt.Sprintf(
					"%s: parameter '%s' should not have a default value. "+
						"Either pass the value from the config file and master stack or use a Mapping",
					template, name))
			}
		}

		errs = append(errs, cfnValidateBuckets(template, body.Resources)...)
		errs = append(errs, cfnValidateCustomResources(template, body.Resources)...)
	}

	errs = append(errs, cfnValidateMaster(parsed)...)

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// Ensure all buckets block HTTP access. Returns a list of error messages.
func cfnValidateBuckets(template string, resources map[string]cfnResource) []string {
	// We don't evaluate the bucket policy logic, we just check that every bucket has an associated
	// "ForceSSL" statement ID attached to its bucket policy.

	// Map bucket resource logical ID to true if we found an associated ForceSSL policy.
	buckets := make(map[string]bool)

	for logicalID, resource := range resources {
		switch resource.Type {
		case "AWS::S3::Bucket":
			if _, exists := buckets[logicalID]; !exists {
				buckets[logicalID] = false
			}

		case "AWS::S3::BucketPolicy":
			bucketID := resource.Properties["Bucket"].(map[string]interface{})["Ref"].(string)
			policy := resource.Properties["PolicyDocument"].(map[string]interface{})
			for _, stmt := range policy["Statement"].([]interface{}) {
				if stmt.(map[string]interface{})["Sid"] == "ForceSSL" {
					buckets[bucketID] = true
					break
				}
			}
		}
	}

	var errs []string
	for bucketID, hasPolicy := range buckets {
		if !hasPolicy {
			errs = append(errs, fmt.Sprintf(
				"%s: S3 bucket %s needs an associated ForceSSL policy statement ID", template, bucketID))
		}
	}
	return errs
}

// Enforce custom resources in a CloudFormation template. Returns a list of error messages.
func cfnValidateCustomResources(template string, resources map[string]cfnResource) []string {
	if template == cfnstacks.BootstrapTemplate {
		// Custom resources can't be in the bootstrap stack
		for logicalID, resource := range resources {
			if strings.HasPrefix(resource.Type, "Custom::") {
				return []string{fmt.Sprintf(
					"%s: %s: custom resources will not work in this stack - use %s instead",
					template, logicalID, cfnstacks.Gateway)}
			}
		}

		// Skip remaining checks
		return nil
	}

	// Right now, we just check logicalID and type, but we can always add additional validation
	// of the resource properties in the future if needed.
	var errs []string
	for logicalID, resource := range resources {
		var err error
		switch resource.Type {
		case "AWS::DynamoDB::Table":
			if resources[logicalID+"Alarms"].Type != "Custom::DynamoDBAlarms" {
				err = fmt.Errorf("%s needs an associated %s resource in %s",
					logicalID, logicalID+"Alarms", template)
			}
		case "AWS::Serverless::Api":
			if resources[logicalID+"Alarms"].Type != "Custom::ApiGatewayAlarms" {
				err = fmt.Errorf("%s needs an associated %s resource in %s",
					logicalID, logicalID+"Alarms", template)
			}
		case "AWS::Serverless::Function":
			err = cfnTestFunction(logicalID, template, resources)
		case "AWS::SNS::Topic":
			if resources[logicalID+"Alarms"].Type != "Custom::SNSAlarms" {
				err = fmt.Errorf("%s needs an associated %s resource in %s",
					logicalID, logicalID+"Alarms", template)
			}
		case "AWS::SQS::Queue":
			if resources[logicalID+"Alarms"].Type != "Custom::SQSAlarms" {
				err = fmt.Errorf("%s needs an associated %s resource in %s",
					logicalID, logicalID+"Alarms", template)
			}
		case "AWS::StepFunctions::StateMachine":
			if resources[logicalID+"Alarms"].Type != "Custom::StateMachineAlarms" {
				err = fmt.Errorf("%s needs an associated %s resource in %s",
					logicalID, logicalID+"Alarms", template)
			}
		}

		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	return errs
}

// Returns an error if an AWS::Serverless::Function is missing associated resources
func cfnTestFunction(logicalID, template string, resources map[string]cfnResource) error {
	idPrefix := strings.TrimSuffix(logicalID, "Function")
	if resources[idPrefix+"MetricFilters"].Type != "Custom::LambdaMetricFilters" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"MetricFilters", template)
	}

	if resources[idPrefix+"Alarms"].Type != "Custom::LambdaAlarms" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"Alarms", template)
	}

	// Backwards compatibility - these resources did not originally match the naming scheme,
	// renaming the logical IDs would delete + recreate the log group, which usually causes
	// deployments to fail because it tries to create a log group which already exists.
	if template == cfnstacks.LogAnalysisTemplate {
		switch idPrefix {
		case "AlertsForwarder":
			idPrefix = "AlertForwarder"
		case "Updater":
			idPrefix = "UpdaterFunction"
		}
	}

	if resources[idPrefix+"LogGroup"].Type != "AWS::Logs::LogGroup" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"LogGroup", template)
	}

	return nil
}

// Validate pre-packaged master template (cfn-lint does not handle cross-stack validation)
//   - Parameters passed to nested stacks are correct
//   - All referenced outputs exist in other stacks
//
// Returns list of error messages.
func cfnValidateMaster(parsed map[string]cfnTemplate) []string {
	var errs []string

	masterResources := parsed["deployments/root.yml"].Resources
	for resourceID, resource := range masterResources {
		if resource.Type != "AWS::CloudFormation::Stack" || resource.Properties["Parameters"] == nil {
			continue
		}

		templatePath := resolvedTemplatePath(resource)
		// Compare the parameters passed in the master stack to those defined in the nested stack
		// Note: all nested stack parameters are required
		passedParams := resource.Properties["Parameters"].(map[string]interface{})
		for paramName := range parsed[templatePath].Parameters {
			if _, exists := passedParams[paramName]; !exists {
				errs = append(errs, fmt.Sprintf(
					"deployments/root.yml: %s: missing required parameter %s",
					resourceID, paramName))
			}
		}

		for paramName := range passedParams {
			if _, exists := parsed[templatePath].Parameters[paramName]; !exists {
				errs = append(errs, fmt.Sprintf(
					"deployments/root.yml: %s: parameter %s does not exist",
					resourceID, paramName))
			}
		}

		// Ensure all stack output references are valid. For example,
		//    !GetAtt Bootstrap.Outputs.AlarmTopicArn
		//
		// will be parsed as:
		//    {"Fn::GetAtt": ["Bootstrap", "Outputs.AlarmTopicArn"]}
		for name, value := range passedParams {
			valMap, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			getAtt, ok := valMap["Fn::GetAtt"].([]interface{})
			if !ok {
				continue
			}

			stack := getAtt[0].(string)
			if masterResources[stack].Type != "AWS::CloudFormation::Stack" {
				// Some other !GetAtt, not a cross-stack reference
				continue
			}
			output := strings.TrimPrefix(getAtt[1].(string), "Outputs.")

			// Look up the outputs of the referenced stack
			refPath := resolvedTemplatePath(masterResources[stack])
			if _, exists := parsed[refPath].Outputs[output]; !exists {
				errs = append(errs, fmt.Sprintf(
					"deployments/root.yml: %s.Properties.Parameters.%s: output %s does not exist in %s",
					resourceID, name, output, stack))
			}
		}
	}

	return errs
}

// Given a stack resource, return the templateURL relative to the repo root
func resolvedTemplatePath(stackResource cfnResource) string {
	templateURL := filepath.Base(stackResource.Properties["TemplateURL"].(string))
	return filepath.Join("deployments", templateURL)
}

func testTfValidate() error {
	root := filepath.Join("deployments", "auxiliary", "terraform")
	paths, err := ioutil.ReadDir(root)
	if err != nil {
		return fmt.Errorf("failed to list tf templates: %v", err)
	}

	// Terraform validate needs a valid AWS region to "configure" the provider.
	// No AWS calls are actually necessary; this can be any region.
	env := map[string]string{"AWS_REGION": "us-east-1"}

	for _, info := range paths {
		if !info.IsDir() {
			continue
		}

		dir := filepath.Join(root, info.Name())
		if err := sh.Run(util.Terraform, "init", "-backend=false", "-input=false", dir); err != nil {
			return fmt.Errorf("tf init %s failed: %v", dir, err)
		}

		if err := sh.RunWith(env, util.Terraform, "validate", dir); err != nil {
			return fmt.Errorf("tf validate %s failed: %v", dir, err)
		}
	}

	return nil
}
