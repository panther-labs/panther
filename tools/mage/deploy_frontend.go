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
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/joho/godotenv"
	"github.com/magefile/mage/sh"
)

const (
	awsEnvFile       = "out/.env.aws"
	frontendStack    = "panther-app-frontend"
	frontendTemplate = "deployments/frontend.yml"
)

func deployFrontend(awsSession *session.Session, bucket string, backendOutputs map[string]string, config *PantherConfig) {
	if err := generateDotEnvFromCfnOutputs(awsSession, backendOutputs); err != nil {
		logger.Fatalf("failed to write ENV variables to file %s: %v", awsEnvFile, err)
	}

	dockerImage, err := buildAndPushImageFromSource(awsSession, backendOutputs["WebApplicationImageRegistry"])
	if err != nil {
		logger.Fatal(err)
	}

	params := map[string]string{
		"WebApplicationFargateTaskCPU":              strconv.Itoa(config.FrontendParameterValues.WebApplicationFargateTaskCPU),
		"WebApplicationFargateTaskMemory":           strconv.Itoa(config.FrontendParameterValues.WebApplicationFargateTaskMemory),
		"WebApplicationImage":                       dockerImage,
		"WebApplicationClusterName":                 backendOutputs["WebApplicationClusterName"],
		"WebApplicationVpcId":                       backendOutputs["WebApplicationVpcId"],
		"WebApplicationSubnetOneId":                 backendOutputs["WebApplicationSubnetOneId"],
		"WebApplicationSubnetTwoId":                 backendOutputs["WebApplicationSubnetTwoId"],
		"WebApplicationLoadBalancerListenerArn":     backendOutputs["WebApplicationLoadBalancerListenerArn"],
		"WebApplicationLoadBalancerSecurityGroupId": backendOutputs["WebApplicationLoadBalancerSecurityGroupId"],
	}
	deployTemplate(awsSession, frontendTemplate, bucket, frontendStack, params)
}

// Accepts Cloudformation outputs, converts the keys into a screaming snakecase format and stores them in a dotenv file
func generateDotEnvFromCfnOutputs(awsSession *session.Session, outputs map[string]string) error {
	conventionalOutputs := map[string]string{
		"AWS_REGION":                           *awsSession.Config.Region,
		"AWS_ACCOUNT_ID":                       outputs["AWSAccountId"],
		"WEB_APPLICATION_GRAPHQL_API_ENDPOINT": outputs["WebApplicationGraphqlApiEndpoint"],
		"WEB_APPLICATION_USER_POOL_ID":         outputs["WebApplicationUserPoolId"],
		"WEB_APPLICATION_USER_POOL_CLIENT_ID":  outputs["WebApplicationUserPoolClientId"],
	}
	return godotenv.Write(conventionalOutputs, awsEnvFile)
}

// Build a personalized docker image from source and push it to the private image repo of the user
func buildAndPushImageFromSource(awsSession *session.Session, imageRegistry string) (string, error) {
	logger.Debug("deploy: requesting access to remote image repo")
	response, err := ecr.New(awsSession).GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get ecr auth token: %v", err)
	}

	ecrAuthorizationToken := *response.AuthorizationData[0].AuthorizationToken
	ecrServer := *response.AuthorizationData[0].ProxyEndpoint

	decodedCredentialsInBytes, err := base64.StdEncoding.DecodeString(ecrAuthorizationToken)
	if err != nil {
		return "", fmt.Errorf("failed to base64-decode ecr auth token: %v", err)
	}
	credentials := strings.Split(string(decodedCredentialsInBytes), ":") // username:password

	if err := dockerLogin(ecrServer, credentials[0], credentials[1]); err != nil {
		return "", err
	}

	logger.Info("deploy: docker build web server (deployments/web/Dockerfile)")
	dockerBuildOutput, err := sh.Output("docker", "build", "--file", "deployments/web/Dockerfile", "--quiet", ".")
	if err != nil {
		return "", fmt.Errorf("docker build failed: %v", err)
	}

	localImageID := strings.Replace(dockerBuildOutput, "sha256:", "", 1)
	remoteImage := imageRegistry + ":" + localImageID

	if err = sh.Run("docker", "tag", localImageID, remoteImage); err != nil {
		return "", fmt.Errorf("docker tag %s %s failed: %v", localImageID, remoteImage, err)
	}

	logger.Info("deploy: pushing docker image to remote repo")
	if err := sh.Run("docker", "push", remoteImage); err != nil {
		return "", fmt.Errorf("docker push failed: %v", err)
	}

	return remoteImage, nil
}

func dockerLogin(ecrServer, username, password string) error {
	// We are going to replace Stdin with a pipe reader, so temporarily
	// cache previous Stdin
	existingStdin := os.Stdin
	// Make sure to reset the Stdin.
	defer func() {
		os.Stdin = existingStdin
	}()
	// Create a pipe to pass docker password to the docker login command
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to open pipe: %v", err)
	}
	os.Stdin = pipeReader

	// Write password to pipe
	if _, err = pipeWriter.WriteString(password); err != nil {
		return fmt.Errorf("failed to write password to pipe: %v", err)
	}
	if err = pipeWriter.Close(); err != nil {
		return fmt.Errorf("failed to close password pipe: %v", err)
	}

	logger.Info("deploy: logging in to remote image repo")
	err = sh.Run("docker", "login",
		"-u", username,
		"--password-stdin",
		ecrServer,
	)
	if err != nil {
		return fmt.Errorf("docker login failed: %v", err)
	}
	return nil
}
