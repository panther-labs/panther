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
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/config"
)

// Returns stack outputs
func deployFrontend(
	awsSession *session.Session,
	bucket string,
	bootstrapOutputs map[string]string,
	settings *config.PantherConfig,
) (map[string]string, error) {

	dockerImage, err := buildAndPushImageFromSource(awsSession, bootstrapOutputs["ImageRegistry"], "")
	if err != nil {
		return nil, err
	}

	params := map[string]string{
		"AlarmTopicArn":              bootstrapOutputs["AlarmTopicArn"],
		"SubnetOneId":                bootstrapOutputs["SubnetOneId"],
		"SubnetTwoId":                bootstrapOutputs["SubnetTwoId"],
		"ElbArn":                     bootstrapOutputs["LoadBalancerArn"],
		"ElbFullName":                bootstrapOutputs["LoadBalancerFullName"],
		"ElbTargetGroup":             bootstrapOutputs["LoadBalancerTargetGroup"],
		"SecurityGroup":              bootstrapOutputs["WebSecurityGroup"],
		"GraphQLApiEndpoint":         bootstrapOutputs["GraphQLApiEndpoint"],
		"UserPoolId":                 bootstrapOutputs["UserPoolId"],
		"AppClientId":                bootstrapOutputs["AppClientId"],
		"Image":                      dockerImage,
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CertificateArn":             settings.Web.CertificateArn,
		"PantherVersion":             gitVersion,
	}
	return deployTemplate(awsSession, frontendTemplate, bucket, frontendStack, params)
}

// Build a personalized docker image from source and push it to the private image repo of the user
func buildAndPushImageFromSource(awsSession *session.Session, imageRegistry, tag string) (string, error) {
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

	logger.Info("deploy: docker build web server (deployments/Dockerfile)")
	dockerBuildOutput, err := sh.Output("docker", "build", "--file", "deployments/Dockerfile", "--quiet", ".")
	if err != nil {
		return "", fmt.Errorf("docker build failed: %v", err)
	}

	localImageID := strings.Replace(dockerBuildOutput, "sha256:", "", 1)
	if tag == "" {
		tag = localImageID
	}
	remoteImage := imageRegistry + ":" + tag

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
