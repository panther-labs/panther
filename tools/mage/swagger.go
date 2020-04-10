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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	apiTemplate         = "deployments/bootstrap_gateway.yml"
	apiEmbeddedTemplate = "out/deployments/embedded.bootstrap_gateway.yml"

	pantherLambdaKey = "x-panther-lambda-handler" // top-level key in Swagger file
	space8           = "        "
)

// Match "DefinitionBody: api/myspec.yml  # possible comment"
var swaggerPattern = regexp.MustCompile(`\n {6}DefinitionBody:[ \t]*[\w./]+\.yml[ \t]*(#.+)?`)

// Embed swagger specs into the API gateway template, saving it to out/deployments.
func embedAPISpec() error {
	cfn := readFile(apiTemplate)

	newCfn, err := embedAPIs(cfn)
	if err != nil {
		return err
	}

	// Save the new file
	if err := os.MkdirAll(filepath.Dir(apiEmbeddedTemplate), 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(apiEmbeddedTemplate), err)
	}

	logger.Debugf("deploy: transformed %s => %s with embedded APIs", apiTemplate, apiEmbeddedTemplate)
	writeFile(apiEmbeddedTemplate, newCfn)
	return nil
}

// Transform a single CloudFormation template by embedding Swagger definitions.
func embedAPIs(cfn []byte) ([]byte, error) {
	var err error

	cfn = swaggerPattern.ReplaceAllFunc(cfn, func(match []byte) []byte {
		strMatch := strings.TrimSpace(string(match))
		apiFilename := strings.Split(strMatch, " ")[1]

		var body *string
		body, err = loadSwagger(apiFilename)
		if err != nil {
			return nil // stop here and the top-level err will be returned
		}

		return []byte("\n      DefinitionBody:\n" + *body)
	})

	return cfn, err
}

// Load and transform a Swagger api.yml file for embedding in CloudFormation.
//
// This is required so we can interpolate the Region and AccountID - API gateway needs to know
// the ARN of the Lambda function being invoked for each endpoint. The interpolation does not work
// if we just reference a swagger file in S3 - the api spec must be embedded into the CloudFormation itself.
func loadSwagger(filename string) (*string, error) {
	var apiBody map[string]interface{}
	if err := yaml.Unmarshal(readFile(filename), &apiBody); err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %v", filename, err)
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

	handlerFunction := apiBody[pantherLambdaKey].(string)
	if handlerFunction == "" {
		return nil, fmt.Errorf("%s must be defined in swagger file %s", pantherLambdaKey, filename)
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
						"arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:" + handlerFunction,
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
		return nil, fmt.Errorf("failed to marshal swagger-embedded yaml: %v", err)
	}

	// Add spaces for the correct indentation when embedding.
	result := space8 + strings.ReplaceAll(strings.TrimSpace(string(newBody)), "\n", "\n"+space8)
	return &result, nil
}
