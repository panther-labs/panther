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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/magefile/mage/sh"
)

// Functions that build a personalized docker image from source, while pushing it to the private image repo of the user
func buildAndPushImageFromSource(awsSession *session.Session, imageTag string) error {
	fmt.Println("deploy: Requesting access to remote image repo")
	ecrClient := ecr.New(awsSession)
	req, resp := ecrClient.GetAuthorizationTokenRequest(&ecr.GetAuthorizationTokenInput{})
	if err := req.Send(); err != nil {
		return err
	}

	ecrAuthorizationToken := *resp.AuthorizationData[0].AuthorizationToken
	ecrServer := *resp.AuthorizationData[0].ProxyEndpoint

	decodedCredentialsInBytes, err := base64.StdEncoding.DecodeString(ecrAuthorizationToken)
	if err != nil {
		return err
	}
	credentials := strings.Split(string(decodedCredentialsInBytes), ":")

	fmt.Println("deploy: logging in to remote image repo")
	if err := sh.Run("docker", "login",
		"-u", credentials[0],
		"-p", credentials[1],
		ecrServer,
	); err != nil {
		return err
	}

	fmt.Println("deploy: building the docker image for the front-end server from source")
	if err := sh.Run("docker", "build",
		"--file", "deployments/web/Dockerfile",
		"--tag", imageTag,
		"--quiet",
		".",
	); err != nil {
		return err
	}

	fmt.Println("deploy: pushing docker image to remote repo")
	if err := sh.RunV("docker", "push", imageTag); err != nil {
		return err
	}

	return nil
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

// makes sure to force a new ECS deployment on the service server so that the latest docker image can be applied
func restartFrontendServer(awsSession *session.Session, cluster string, service string) error {
	fmt.Println("deploy: upgrading front-end server to the latest docker image")
	ecsClient := ecs.New(awsSession)
	_, err := ecsClient.UpdateService(&ecs.UpdateServiceInput{
		Cluster:            aws.String(cluster),
		Service:            aws.String(service),
		ForceNewDeployment: aws.Bool(true),
	})
	if err != nil {
		return err
	}

	fmt.Println("deploy: front-end server upgraded successfully!")
	color.Cyan("deploy: please allow up to 1 minute for front-end changes to be propagated across containers")
	return nil
}
