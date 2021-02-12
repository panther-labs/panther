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
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"go.uber.org/zap"
)

// Returns local image ID (truncated SHA256)
func DockerBuild(log *zap.SugaredLogger, dockerfile string) (string, error) {
	tmpfile, err := ioutil.TempFile("", "panther-web-image-id")
	if err != nil {
		return "", fmt.Errorf("failed to create temp image ID file: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	args := []string{"build", "--file", dockerfile, "--iidfile", tmpfile.Name()}
	if !mg.Verbose() {
		args = append(args, "--quiet")
	}
	args = append(args, ".")

	log.Infof("docker %s", strings.Join(args, " "))
	// When running without the "--quiet" flag, docker build has no stdout we can capture.
	// Instead, we use --iidfile to write the image ID to a tmp file and read it back.
	err = sh.RunV("docker", args...)
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
func (p Packager) DockerPush(tag string) (string, error) {
	p.Log.Debug("requesting ecr auth token")
	response, err := ecr.NewFromConfig(p.AwsConfig).GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{})
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
		tag = p.DockerImageID
	}
	remoteImage := p.EcrRegistry + ":" + tag

	if err = sh.Run("docker", "tag", p.DockerImageID, remoteImage); err != nil {
		return "", fmt.Errorf("docker tag %s %s failed: %v", p.DockerImageID, remoteImage, err)
	}

	p.Log.Infof("pushing docker image %s to remote repo", remoteImage)
	if err := sh.RunV("docker", "push", remoteImage); err != nil {
		return "", err
	}

	return remoteImage, nil
}

func dockerLogin(ecrServer, username, password string) error {
	// We are going to replace Stdin with a pipe reader, so temporarily
	// cache previous Stdin
	existingStdin := os.Stdin

	// Create a pipe to pass docker password to the docker login command
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to open pipe: %v", err)
	}

	// Reset stdin and close resources
	defer func() {
		os.Stdin = existingStdin
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
	}()

	os.Stdin = pipeReader

	// Write password to pipe
	if _, err = pipeWriter.WriteString(password); err != nil {
		return fmt.Errorf("failed to write password to pipe: %v", err)
	}
	if err = pipeWriter.Close(); err != nil { // writer must be closed now to finish the login
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
