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
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/joho/godotenv"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/util"
)

const awsEnvFile = "out/.env.aws"

func deployFrontend(bootstrapOutputs map[string]string, settings *PantherConfig) error {
	// Save .env file (only used when running web server locally)
	if err := godotenv.Write(
		map[string]string{
			"AWS_ACCOUNT_ID":                       clients.AccountID(),
			"AWS_REGION":                           clients.Region(),
			"WEB_APPLICATION_GRAPHQL_API_ENDPOINT": bootstrapOutputs["GraphQLApiEndpoint"],
			"WEB_APPLICATION_USER_POOL_ID":         bootstrapOutputs["UserPoolId"],
			"WEB_APPLICATION_USER_POOL_CLIENT_ID":  bootstrapOutputs["AppClientId"],
		},
		awsEnvFile,
	); err != nil {
		return fmt.Errorf("failed to write ENV variables to file %s: %v", awsEnvFile, err)
	}

	localImageID, err := DockerBuild()
	if err != nil {
		return err
	}

	dockerImage, err := DockerPush(bootstrapOutputs["ImageRegistryUri"], localImageID, "")
	if err != nil {
		return err
	}

	params := map[string]string{
		"AlarmTopicArn":              bootstrapOutputs["AlarmTopicArn"],
		"AppClientId":                bootstrapOutputs["AppClientId"],
		"CertificateArn":             settings.Web.CertificateArn,
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomResourceVersion":      customResourceVersion(),
		"ElbArn":                     bootstrapOutputs["LoadBalancerArn"],
		"ElbFullName":                bootstrapOutputs["LoadBalancerFullName"],
		"ElbTargetGroup":             bootstrapOutputs["LoadBalancerTargetGroup"],
		"FirstUserEmail":             settings.Setup.FirstUser.Email,
		"FirstUserFamilyName":        settings.Setup.FirstUser.FamilyName,
		"FirstUserGivenName":         settings.Setup.FirstUser.GivenName,
		"GraphQLApiEndpoint":         bootstrapOutputs["GraphQLApiEndpoint"],
		"Image":                      dockerImage,
		"InitialAnalysisPackUrls":    strings.Join(settings.Setup.InitialAnalysisSets, ","),
		"PantherVersion":             util.RepoVersion(),
		"SecurityGroup":              bootstrapOutputs["WebSecurityGroup"],
		"SubnetOneId":                bootstrapOutputs["SubnetOneId"],
		"SubnetTwoId":                bootstrapOutputs["SubnetTwoId"],
		"UserPoolId":                 bootstrapOutputs["UserPoolId"],
	}
	_, err = deployTemplate(cfnstacks.FrontendTemplate, bootstrapOutputs["SourceBucket"], cfnstacks.Frontend, params)
	return err
}

// Returns local image ID
func DockerBuild() (string, error) {
	log.Info("docker build web server (deployments/Dockerfile)")
	dockerBuildOutput, err := sh.Output("docker", "build", "--file", "deployments/Dockerfile", "--quiet", ".")
	if err != nil {
		return "", fmt.Errorf("docker build failed: %v", err)
	}

	return strings.Replace(dockerBuildOutput, "sha256:", "", 1), nil
}

// Build a personalized docker image from source and push it to the private image repo of the user
func DockerPush(imageRegistry, localImageID, tag string) (string, error) {
	log.Debug("requesting access to remote image repo")
	response, err := clients.ECR().GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
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

	if tag == "" {
		tag = localImageID
	}
	remoteImage := imageRegistry + ":" + tag

	if err = sh.Run("docker", "tag", localImageID, remoteImage); err != nil {
		return "", fmt.Errorf("docker tag %s %s failed: %v", localImageID, remoteImage, err)
	}

	log.Infof("pushing docker image %s to remote repo", remoteImage)
	if err := sh.Run("docker", "push", remoteImage); err != nil {
		return "", err
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
