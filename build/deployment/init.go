package main

import (
	"github.com/magefile/mage/sh"
	"log"
	"os"
)

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	_, err = sh.Exec(nil, os.Stdout, os.Stderr, "docker", "run",
		// add the local panther directory as a mount volume
		"-v", pwd + ":/code",
		// use the same docker daemon within the image, as the one present in the host machine
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		// forward the needed ENV vars to the container
		"-e", "AWS_ACCESS_KEY_ID",
		"-e", "AWS_SECRET_ACCESS_KEY",
		"-e", "AWS_REGION",
		// run in interractive mode
		"-it",
		// don't store a container out of this execution (since temporary creds could be still compromised)
		"--rm",
		"pantherlabs/panther-deployment-pack:latest",
	)
	if err != nil {
		log.Fatal(err)
	}
}
