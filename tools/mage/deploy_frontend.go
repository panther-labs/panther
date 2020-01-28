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
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/joho/godotenv"
	"github.com/magefile/mage/sh"
)

// Functions that build a personalized docker image from source, while pushing it to the private image repo of the user
func buildAndPushImageFromSource(awsSession *session.Session, imageRegistry string) (string, error) {
	fmt.Println("deploy: requesting access to remote image repo")
	ecrClient := ecr.New(awsSession)
	req, resp := ecrClient.GetAuthorizationTokenRequest(&ecr.GetAuthorizationTokenInput{})
	if err := req.Send(); err != nil {
		return "", err
	}

	ecrAuthorizationToken := *resp.AuthorizationData[0].AuthorizationToken
	ecrServer := *resp.AuthorizationData[0].ProxyEndpoint

	decodedCredentialsInBytes, err := base64.StdEncoding.DecodeString(ecrAuthorizationToken)
	if err != nil {
		return "", err
	}
	credentials := strings.Split(string(decodedCredentialsInBytes), ":")

	if err := dockerLogin(ecrServer, credentials); err != nil {
		return "", err
	}

	fmt.Println("deploy: building the docker image for the front-end server from source")
	dockerBuildOutput, err := sh.Output("docker", "build", "--file", "deployments/web/Dockerfile", "--quiet", ".")
	if err != nil {
		return "", err
	}

	localImageID := strings.Replace(dockerBuildOutput, "sha256:", "", 1)
	remoteImage := imageRegistry + ":" + localImageID

	fmt.Println("deploy: tagging the new image release")
	if err = sh.Run("docker", "tag", localImageID, remoteImage); err != nil {
		return "", err
	}

	fmt.Println("deploy: pushing docker image to remote repo")
	if err := sh.RunV("docker", "push", remoteImage); err != nil {
		return "", err
	}

	return remoteImage, nil
}

func dockerLogin(ecrServer string, dockerCredentials []string) error {
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
		return err
	}
	os.Stdin = pipeReader

	// Write password to pipe
	if _, err := pipeWriter.WriteString(dockerCredentials[1]); err != nil {
		return err
	}
	if err := pipeWriter.Close(); err != nil {
		return err
	}

	fmt.Println("deploy: logging in to remote image repo")
	return sh.Run("docker", "login",
		"-u", dockerCredentials[0],
		"--password-stdin",
		ecrServer,
	)
}

// Accepts Cloudformation outputs, converts the keys into a screaming snakecase format and stores them in a dotenv file
func generateDotEnvFromCfnOutputs(awsSession *session.Session, outputs map[string]string, filename string) error {
	conventionalOutputs := map[string]string{
		"AWS_REGION":                           *awsSession.Config.Region,
		"AWS_ACCOUNT_ID":                       outputs["AWSAccountId"],
		"WEB_APPLICATION_GRAPHQL_API_ENDPOINT": outputs["WebApplicationGraphqlApiEndpoint"],
		"WEB_APPLICATION_USER_POOL_ID":         outputs["WebApplicationUserPoolId"],
		"WEB_APPLICATION_USER_POOL_CLIENT_ID":  outputs["WebApplicationUserPoolClientId"],
	}

	if err := godotenv.Write(conventionalOutputs, filename); err != nil {
		return err
	}
	return nil
}
