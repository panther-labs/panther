package build

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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

var log = logger.Get()

// Generate API source files from GraphQL + Swagger
func API() {
	mg.Deps(generateSwaggerClients, generateWebTypescript, goGenerate)
}

func goGenerate() error {
	const generatePattern = "./..."
	log.Info("build:api: generating Go code with go:generate")
	if err := sh.Run("go", "generate", generatePattern); err != nil {
		return fmt.Errorf("go:generate failed: %s", err)
	}
	return nil
}

func generateSwaggerClients() error {
	const swaggerGlob = "api/gateway/*/api.yml"
	specs, err := filepath.Glob(swaggerGlob)
	if err != nil {
		return fmt.Errorf("failed to glob %s: %v", swaggerGlob, err)
	}

	log.Infof("build:api: generating Go SDK for %d APIs (%s)", len(specs), swaggerGlob)

	cmd := util.Swagger
	if _, err = os.Stat(util.Swagger); err != nil {
		return fmt.Errorf("%s not found (%v): run 'mage setup'", cmd, err)
	}

	// This import has to be fixed, see below
	clientImport := regexp.MustCompile(
		`"github.com/panther-labs/panther/api/gateway/[a-z]+/client/operations"`)

	for _, spec := range specs {
		dir := filepath.Dir(spec)
		client, models := filepath.Join(dir, "client"), filepath.Join(dir, "models")

		args := []string{"generate", "client", "-q", "-f", spec, "-c", client, "-m", models}
		if err := sh.Run(cmd, args...); err != nil {
			return fmt.Errorf("%s %s failed: %v", cmd, strings.Join(args, " "), err)
		}

		// TODO - delete unused models
		// If an API model is removed, "swagger generate" will leave the Go file in place.
		// We tried to remove generated files based on timestamp, but that had issues in Docker.
		// We tried removing the client/ and models/ every time, but mage itself depends on some of these.
		// For now, developers just need to manually remove unused swagger models.

		// There is a bug in "swagger generate" which can lead to incorrect import paths.
		// To reproduce: comment out this section, clone to /tmp and "mage build:api" - note the diffs.
		// The most reliable workaround has been to just rewrite the import ourselves.
		//
		// For example, in api/gateway/remediation/client/panther_remediation_client.go:
		//     import "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
		// should be
		//     import "github.com/panther-labs/panther/api/gateway/remediation/client/operations"
		util.Walk(client, func(path string, info os.FileInfo) {
			if info.IsDir() || filepath.Ext(path) != ".go" {
				return
			}

			body, err := ioutil.ReadFile(path)
			if err != nil {
				log.Fatalf("failed to open %s: %v", path, err)
			}

			correctImport := fmt.Sprintf(
				`"github.com/panther-labs/panther/api/gateway/%s/client/operations"`,
				filepath.Base(filepath.Dir(filepath.Dir(path))))

			newBody := clientImport.ReplaceAll(body, []byte(correctImport))
			if err := ioutil.WriteFile(path, newBody, info.Mode()); err != nil {
				log.Fatalf("failed to rewrite %s: %v", path, err)
			}
		})
	}
	return nil
}

func generateWebTypescript() error {
	log.Info("build:api: generating web typescript from graphql")
	if err := sh.Run("npm", "run", "graphql-codegen"); err != nil {
		return fmt.Errorf("graphql generation failed: %v", err)
	}
	return nil
}
