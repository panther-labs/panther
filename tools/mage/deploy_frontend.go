package mage

import (
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/fatih/color"
	"github.com/magefile/mage/sh"
	"strings"
)

// Functions that build a personalized docker image from source, while pushing it to the private image repo of the user
func buildAndPushImageFromSource(awsSession *session.Session, imageTag string) error {
	fmt.Println("docker: Requesting access to remote image repo")
	ecrClient := ecr.New(awsSession)
	req, resp := ecrClient.GetAuthorizationTokenRequest(&ecr.GetAuthorizationTokenInput{})
	if err := req.Send(); err != nil {
		return err
	}

	ecrAuthorizationToken := *resp.AuthorizationData[0].AuthorizationToken
	ecrServer := *resp.AuthorizationData[0].ProxyEndpoint

	decodedCredentialsInBytes, _ := base64.StdEncoding.DecodeString(ecrAuthorizationToken)
	credentials := strings.Split(string(decodedCredentialsInBytes), ":")

	fmt.Println("deploy: logging in to remote image repo")
	if err := sh.Run("docker", "login",
		"-u", credentials[0],
		"-p", credentials[1],
		ecrServer,
	); err != nil {
		return err
	}

	fmt.Println("deploy: building docker image from source")
	if err := sh.Run("docker", "build",
		"--file", "deployments/web/Dockerfile",
		"--tag", imageTag,
		"--quiet",
		".",
	); err != nil {
		return err
	}

	fmt.Println("deploy: pushing image to remote repo")
	if err := sh.RunV("docker", "push", imageTag); err != nil {
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
