package gen

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
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/tools/mage/gen/dashboards"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

var log = logger.Build("[gen]")

// Autogenerate parts of the source code: API SDKs, GraphQL types, CW dashboards
func Gen() error {
	results := make(chan util.TaskResult)
	count := 0

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "swagger clients", Err: swaggerClients()}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "go generate", Err: goGenerate()}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "graphQL", Err: graphQLCodegen()}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "cw dashboards", Err: cwDashboards()}
	}(results)

	return util.WaitForTasks(log, results, 1, count, count)
}

func swaggerClients() error {
	const swaggerGlob = "api/gateway/*/api.yml"
	specs, err := filepath.Glob(swaggerGlob)
	if err != nil {
		return fmt.Errorf("failed to glob %s: %v", swaggerGlob, err)
	}

	log.Debugf("generating Go SDK for %d APIs (%s)", len(specs), swaggerGlob)

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
		// To reproduce: comment out this section, clone to /tmp and "mage gen" - note the diffs.
		// The most reliable workaround has been to just rewrite the import ourselves.
		//
		// For example, in api/gateway/remediation/client/panther_remediation_client.go:
		//     import "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
		// should be
		//     import "github.com/panther-labs/panther/api/gateway/remediation/client/operations"
		util.MustWalk(client, func(path string, info os.FileInfo) error {
			if info.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}

			body := util.MustReadFile(path)
			correctImport := fmt.Sprintf(
				`"github.com/panther-labs/panther/api/gateway/%s/client/operations"`,
				filepath.Base(filepath.Dir(filepath.Dir(path))))

			newBody := clientImport.ReplaceAll(body, []byte(correctImport))
			util.MustWriteFile(path, newBody)
			return nil
		})
	}
	return nil
}

func goGenerate() error {
	const generatePattern = "./..."
	if err := sh.Run("go", "generate", generatePattern); err != nil {
		return fmt.Errorf("go:generate failed: %s", err)
	}
	return nil
}

func graphQLCodegen() error {
	if err := sh.Run("npm", "run", "graphql-codegen"); err != nil {
		return fmt.Errorf("graphql generation failed: %v", err)
	}
	return nil
}

// Generate deployments/dashboards.yml
func cwDashboards() error {
	dashboardResources := dashboards.Dashboards()
	log.Debugf("loaded %d dashboards", len(dashboardResources))

	template := map[string]interface{}{
		"AWSTemplateFormatVersion": "2010-09-09",
		"Description":              "Panther's CloudWatch monitoring dashboards",
	}

	resources := make(map[string]interface{}, len(dashboardResources))
	for _, dashboard := range dashboardResources {
		logicalID := strings.TrimPrefix(dashboard.Properties.DashboardName.Sub, "Panther")
		logicalID = strings.TrimSuffix(logicalID, "-${AWS::Region}")
		resources[logicalID] = dashboard
	}

	template["Resources"] = resources
	body, err := yaml.Marshal(template)
	if err != nil {
		return fmt.Errorf("dashboard yaml marshal failed: %v", err)
	}

	body = append([]byte("# NOTE: template auto-generated by 'mage gen', DO NOT EDIT\n"), body...)

	target := filepath.Join("deployments", "dashboards.yml")
	util.MustWriteFile(target, body)
	return nil
}
