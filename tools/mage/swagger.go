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
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/magefile/mage/mg"
	"gopkg.in/yaml.v2"
)

const (
	pantherLambdaKey = "x-panther-lambda-cfn-resource" // top-level key in Swagger file
	space8           = "        "
)

var (
	swaggerPattern = regexp.MustCompile(`DefinitionBody: api/[^#]+\.yml.*`)
	graphqlPattern = regexp.MustCompile(`Definition: api/[^#]+\.graphql.*`)
)

// Embed swagger/graphql specs into all API CloudFormation templates, saving them to out/deployments.
func embedAPISpecs() error {
	templates, err := filepath.Glob("deployments/*/*.yml")
	if err != nil {
		return err
	}

	for _, template := range templates {
		if _, err := embedAPI(template); err != nil {
			return err
		}
	}

	return nil
}

// Transform a CloudFormation template by embedding Swagger + GraphQL definitions.
//
// Returns the new template path, which may be unchanged if there was nothing to embed.
func embedAPI(cfnFilename string) (string, error) {
	cfn, err := ioutil.ReadFile(cfnFilename)
	if err != nil {
		return "", fmt.Errorf("failed to open CloudFormation template %s: %s", cfnFilename, err)
	}

	var errList []error
	changed := false
	cfn = swaggerPattern.ReplaceAllFunc(cfn, func(match []byte) []byte {
		apiFilename := strings.TrimSpace(strings.Split(string(match), " ")[1])
		if mg.Verbose() {
			fmt.Printf("deploy: %s embedding swagger DefinitionBody: %s\n", cfnFilename, apiFilename)
		}

		body, err := loadSwagger(apiFilename)
		if err != nil {
			errList = append(errList, err)
			return match // return the original string unmodified
		}

		changed = true
		return []byte("DefinitionBody:\n" + *body)
	})

	cfn = graphqlPattern.ReplaceAllFunc(cfn, func(match []byte) []byte {
		apiFilename := strings.TrimSpace(strings.Split(string(match), " ")[1])
		if mg.Verbose() {
			fmt.Printf("deploy: %s embedding graphql Definition: %s\n", cfnFilename, apiFilename)
		}

		graphql, err := ioutil.ReadFile(apiFilename)
		if err != nil {
			errList = append(errList, err)
			return match
		}

		spaced := space8 + strings.ReplaceAll(string(graphql), "\n", "\n"+space8)
		changed = true
		return []byte("Definition: |\n" + spaced)
	})

	if err := JoinErrors("deploy: embedAPI", errList); err != nil {
		return "", err
	}

	if !changed {
		// No changes - return original file
		return cfnFilename, nil
	}

	outputDir := filepath.Join("out", filepath.Dir(cfnFilename))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to build output dir %s: %s", outputDir, err)
	}

	cfnDest := filepath.Join(outputDir, "embedded."+filepath.Base(cfnFilename))
	if err := ioutil.WriteFile(cfnDest, cfn, 0644); err != nil {
		return "", fmt.Errorf("failed to write new CloudFormation template %s: %s", cfnDest, err)
	}

	return cfnDest, nil
}

// Load and transform a Swagger api.yml file for embedding in CloudFormation.
//
// TODO - add unit tests for this function
// This is required so we can interpolate the Region and AccountID - API gateway needs to know
// the ARN of the Lambda function being invoked for each endpoint. The interpolation does not work
// if we just reference a swagger file - the api spec must be embedded into the CloudFormation itself.
func loadSwagger(filename string) (*string, error) {
	var apiBody map[string]interface{}
	if err := loadYamlFile(filename, &apiBody); err != nil {
		return nil, err
	}

	// Allow AWS_IAM authorization (i.e. AWS SIGv4 signatures).
	apiBody["securityDefinitions"] = map[string]interface{}{
		"sigv4": map[string]string{
			"type":                         "apiKey",
			"name":                         "Authorization",
			"in":                           "header",
			"x-amazon-apigateway-authtype": "awsSigv4",
		},
	}

	// API Gateway will validate all requests to the maximum possible extent.
	apiBody["x-amazon-apigateway-request-validators"] = map[string]interface{}{
		"validate-all": map[string]bool{
			"validateRequestParameters": true,
			"validateRequestBody":       true,
		},
	}

	functionResource := apiBody[pantherLambdaKey].(string)
	if functionResource == "" {
		return nil, fmt.Errorf("%s is required in '%s'", pantherLambdaKey, filename)
	}
	delete(apiBody, pantherLambdaKey)

	// Every method requires the same boilerplate settings: validation, sigv4, lambda integration
	for _, endpoints := range apiBody["paths"].(map[interface{}]interface{}) {
		for _, definition := range endpoints.(map[interface{}]interface{}) {
			def := definition.(map[interface{}]interface{})
			def["x-amazon-apigateway-integration"] = map[string]interface{}{
				"httpMethod":          "POST",
				"passthroughBehavior": "never",
				"type":                "aws_proxy",
				"uri": map[string]interface{}{
					"Fn::Sub": strings.Join([]string{
						"arn:aws:apigateway:${AWS::Region}:lambda:path",
						"2015-03-31",
						"functions",
						"arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:${" + functionResource + "}",
						"invocations",
					}, "/"),
				},
			}
			def["x-amazon-apigateway-request-validator"] = "validate-all"
			def["security"] = []map[string]interface{}{
				{"sigv4": []string{}},
			}

			// Replace integer response codes with strings (cfn doesn't support non-string keys).
			responses := def["responses"].(map[interface{}]interface{})
			for code, val := range responses {
				if intcode, ok := code.(int); ok {
					responses[strconv.Itoa(intcode)] = val
					delete(responses, code)
				}
			}
		}
	}

	newBody, err := yaml.Marshal(apiBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified yaml: %s", err)
	}

	// Add spaces for the correct indentation when embedding.
	result := space8 + strings.ReplaceAll(string(newBody), "\n", "\n"+space8)
	return &result, nil
}
