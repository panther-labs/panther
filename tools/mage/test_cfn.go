package mage

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
	{"build:cfn", build.cfn},
	{"cfn-lint", testCfnLint},
	{"terraform validate", testTfValidate},
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

	// Panther-specific linting for main stacks
	//
	// - Required custom resources
	// - No default parameter values
	var errs []string
	for _, template := range templates {
		if template == "deployments/master.yml" || strings.HasPrefix(template, "deployments/auxiliary") {
			continue
		}

		body, err := cfnparse.ParseTemplate(pythonVirtualEnvPath, template)
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to parse %s: %v", template, err))
			continue
		}

		// Parameter defaults should not be defined in the nested stacks. Defaults are defined in:
		//   - the config file, when deploying from source
		//   - the master template, for pre-packaged deployments
		//
		// Allowing defaults in nested stacks is confusing and leads to bugs where a parameter is
		// defined but never passed through during deployment.
		if err = cfnDefaultParameters(body); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", template, err))
		}

		if template == cfnstacks.BootstrapTemplate {
			// Custom resources can't be in the bootstrap stack
			for logicalID, resource := range body["Resources"].(map[string]interface{}) {
				t := resource.(map[string]interface{})["Type"].(string)
				if strings.HasPrefix(t, "Custom::") {
					return fmt.Errorf("%s: %s: custom resources will not work in this stack - use bootstrap-gateway instead",
						template, logicalID)
				}
			}

			// Skip remaining checks
			continue
		}

		// Map logicalID => resource type
		resources := make(map[string]string)
		for logicalID, resource := range body["Resources"].(map[string]interface{}) {
			resources[logicalID] = resource.(map[string]interface{})["Type"].(string)
		}

		// Right now, we just check logicalID and type, but we can always add additional validation
		// of the resource properties in the future if needed.
		for logicalID, resourceType := range resources {
			var err error
			switch resourceType {
			case "AWS::DynamoDB::Table":
				if resources[logicalID+"Alarms"] != "Custom::DynamoDBAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::Serverless::Api":
				if resources[logicalID+"Alarms"] != "Custom::ApiGatewayAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::Serverless::Function":
				err = cfnTestFunction(logicalID, template, resources)
			case "AWS::SNS::Topic":
				if resources[logicalID+"Alarms"] != "Custom::SNSAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::SQS::Queue":
				if resources[logicalID+"Alarms"] != "Custom::SQSAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::StepFunctions::StateMachine":
				if resources[logicalID+"Alarms"] != "Custom::StateMachineAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			}

			if err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// Returns an error if there is a parameter with a default value.
func cfnDefaultParameters(template map[string]interface{}) error {
	params, ok := template["Parameters"].(map[string]interface{})
	if !ok {
		return nil
	}

	for name, options := range params {
		if _, exists := options.(map[string]interface{})["Default"]; exists {
			return fmt.Errorf("parameter '%s' should not have a default value. "+
				"Either pass the value from the config file and master stack or use a Mapping", name)
		}
	}

	return nil
}

// Returns an error if an AWS::Serverless::Function is missing associated resources
func cfnTestFunction(logicalID, template string, resources map[string]string) error {
	idPrefix := strings.TrimSuffix(logicalID, "Function")
	if resources[idPrefix+"MetricFilters"] != "Custom::LambdaMetricFilters" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"MetricFilters", template)
	}

	if resources[idPrefix+"Alarms"] != "Custom::LambdaAlarms" {
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

	if resources[idPrefix+"LogGroup"] != "AWS::Logs::LogGroup" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"LogGroup", template)
	}

	return nil
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
