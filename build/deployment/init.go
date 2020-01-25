package main

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
