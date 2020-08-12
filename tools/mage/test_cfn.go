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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/cfnparse"
	"github.com/panther-labs/panther/tools/cfnstacks"
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
func (Test) Cfn() {
	runTests(cfnTests)
}

func testCfnLint() error {
	var templates []string
	walk("deployments", func(path string, info os.FileInfo) {
		if !info.IsDir() && filepath.Ext(path) == ".yml" && filepath.Base(path) != "panther_config.yml" {
			templates = append(templates, path)
		}
	})

	// cfn-lint will complain:
	//   E3012 Property Resources/SnapshotDLQ/Properties/MessageRetentionPeriod should be of type Integer
	//
	// But if we keep them integers, yaml marshaling converts large integers to scientific notation,
	// which CFN does not understand. So we force string values to serialize them correctly.
	args := []string{"-x", "E3012:strict=false", "--"}
	args = append(args, templates...)
	if err := sh.RunV(pythonLibPath("cfn-lint"), args...); err != nil {
		return err
	}

	// Parse Panther CloudFormation, map template path to parsed body
	parsed := make(map[string]cfnTemplate, cfnstacks.NumStacks+1)
	for _, template := range templates {
		if strings.HasPrefix(template, "deployments/auxiliary") {
			continue
		}

		var body cfnTemplate
		if err := cfnparse.ParseTemplate(pythonVirtualEnvPath, template, &body); err != nil {
			return fmt.Errorf("failed to parse %s: %v", template, err)
		}
		parsed[template] = body
	}

	// Panther-specific linting for main stacks
	//   - No default parameter values
	//   - Required custom resources
	var errs []string
	for template, body := range parsed {
		if template == "deployments/master.yml" {
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

		errs = append(errs, cfnValidateCustomResources(template, body.Resources)...)
	}

	errs = append(errs, cfnValidateMaster(parsed)...)

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
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

	for resourceID, resource := range parsed["deployments/master.yml"].Resources {
		if resource.Type != "AWS::CloudFormation::Stack" || resource.Properties["Parameters"] == nil {
			continue
		}

		templateURL := resource.Properties["TemplateURL"].(string)
		if filepath.Base(templateURL) == "embedded.bootstrap_gateway.yml" {
			// For the purposes of this test, read the original template, not the one with embedded swagger
			templateURL = "bootstrap_gateway.yml"
		}
		templateURL = filepath.Join("deployments", templateURL)

		// Compare the parameters passed in the master stack to those defined in the nested stack
		// Note: all nested stack parameters are required
		passedParams := resource.Properties["Parameters"].(map[string]interface{})
		for paramName := range parsed[templateURL].Parameters {
			if _, exists := passedParams[paramName]; !exists {
				errs = append(errs, fmt.Sprintf(
					"deployments/master.yml: %s is missing required parameter %s",
					resourceID, paramName))
			}
		}

		for paramName := range passedParams {
			if _, exists := parsed[templateURL].Parameters[paramName]; !exists {
				errs = append(errs, fmt.Sprintf(
					"deployments/master.yml: %s: parameter %s does not exist",
					resourceID, paramName))
			}
		}
	}

	return errs
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
		if err := sh.Run(terraformPath, "init", "-backend=false", "-input=false", dir); err != nil {
			return fmt.Errorf("tf init %s failed: %v", dir, err)
		}

		if err := sh.RunWith(env, terraformPath, "validate", dir); err != nil {
			return fmt.Errorf("tf validate %s failed: %v", dir, err)
		}
	}

	return nil
}
