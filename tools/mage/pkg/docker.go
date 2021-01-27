package pkg

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
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/magefile/mage/sh"
)

// Returns local image ID (truncated SHA256)
func (p Packager) DockerBuild(dockerfile string) (string, error) {
	p.Log.Infof("docker build web server (%s)", dockerfile)
	tmpfile, err := ioutil.TempFile("", "panther-web-image-id")
	if err != nil {
		return "", fmt.Errorf("failed to create temp image ID file: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	// When running without the "-q" flag, docker build has no capturable stdout.
	// Instead, we use --iidfile to write the image ID to a tmp file and read it back.
	err = sh.Run("docker", "build",
		"--file", dockerfile, "--iidfile", tmpfile.Name(), ".")
	if err != nil {
		return "", fmt.Errorf("docker build failed: %v", err)
	}

	// "sha256:abcdef...."
	imageID, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		return "", fmt.Errorf("failed to open image ID file: %s", err)
	}

	return strings.TrimPrefix(string(imageID), "sha256:")[:12], nil
}

// Build the web docker image from source and push it to the ecr registry
func (p Packager) DockerPush(localImageID, tag string) (string, error) {
	p.Log.Debug("requesting access to remote image repo")
	ecrClient := ecr.New(p.AwsSession)

	response, err := ecrClient.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
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
	remoteImage := p.EcrRegistry + ":" + tag

	if err = sh.Run("docker", "tag", localImageID, remoteImage); err != nil {
		return "", fmt.Errorf("docker tag %s %s failed: %v", localImageID, remoteImage, err)
	}

	p.Log.Infof("pushing docker image %s to remote repo", remoteImage)
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
