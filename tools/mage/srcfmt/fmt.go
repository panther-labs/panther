package srcfmt

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
	"bytes"
	"encoding/json"
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

var (
	log       = logger.Build("[fmt]")
	goTargets = []string{"api", "internal", "pkg", "tools", "cmd", "magefile.go"}
)

func Fmt() error {
	// Add license headers first (don't run in parallel with other formatters)
	fmtLicenseAll()

	results := make(chan util.TaskResult)
	count := 0

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "gofmt", Err: gofmt(goTargets...)}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "yapf", Err: yapf(util.PyTargets...)}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "prettier", Err: prettier("")}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "tf", Err: terraformFmt()}
	}(results)

	return util.WaitForTasks(log, results, 1, count, count)
}

// Apply full go formatting to the given paths
func gofmt(paths ...string) error {
	log.Debug("gofmt " + strings.Join(paths, " "))

	// 1) gofmt to standardize the syntax formatting with code simplification (-s) flag
	if err := sh.Run("gofmt", append([]string{"-l", "-s", "-w"}, paths...)...); err != nil {
		return fmt.Errorf("gofmt failed: %v", err)
	}

	// 2) Remove empty newlines from import groups
	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("stat %s: %v", path, err)
			}

			if !info.IsDir() && strings.HasSuffix(path, ".go") {
				if err := removeImportNewlines(path); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// 3) Goimports to group imports into 3 sections
	args := append([]string{"-w", "-local=github.com/panther-labs/panther"}, paths...)
	if err := sh.Run("goimports", args...); err != nil {
		return fmt.Errorf("goimports failed: %v", err)
	}

	// 4) go mod tidy
	if err := sh.Run("go", "mod", "tidy"); err != nil {
		return fmt.Errorf("go mod tidy failed: %v", err)
	}

	return nil
}

// Remove empty newlines from formatted import groups so goimports will correctly group them.
func removeImportNewlines(path string) error {
	var newLines [][]byte
	inImport := false
	for _, line := range bytes.Split(util.MustReadFile(path), []byte("\n")) {
		if inImport {
			if len(line) == 0 {
				continue // skip empty newlines in import groups
			}
			if line[0] == ')' { // gofmt always puts the ending paren on its own line
				inImport = false
			}
		} else if bytes.HasPrefix(line, []byte("import (")) {
			inImport = true
		}

		newLines = append(newLines, line)
	}

	return ioutil.WriteFile(path, bytes.Join(newLines, []byte("\n")), 0600)
}

// Apply Python formatting to the given paths
func yapf(paths ...string) error {
	log.Debug("python yapf " + strings.Join(paths, " "))
	args := []string{"--in-place", "--parallel", "--recursive"}
	if err := sh.Run(util.PipPath("yapf"), append(args, util.PyTargets...)...); err != nil {
		return fmt.Errorf("failed to format python: %v", err)
	}
	return nil
}

// Apply prettier formatting to web, markdown, and yml files
func prettier(pathPattern string) error {
	if pathPattern == "" {
		pathPattern = "**/*.{ts,js,tsx,md,json,yaml,yml}"
	}
	log.Debug("prettier " + pathPattern)
	args := []string{"--write", pathPattern}
	if !mg.Verbose() {
		args = append(args, "--loglevel", "error")
	}

	if err := sh.Run(util.NodePath("prettier"), args...); err != nil {
		return fmt.Errorf("failed to format with prettier: %v", err)
	}
	return nil
}

// Apply Terraform formatting to aux templates
func terraformFmt() error {
	if err := tfUpdateDeploymentRole(); err != nil {
		return err
	}
	root := filepath.Join("deployments", "auxiliary", "terraform")
	return sh.Run(util.Terraform, "fmt", "-recursive", root)
}

// Generate terraform version of the deployment role
func tfUpdateDeploymentRole() error {
	// CloudFormation deployment role template structure
	type template struct {
		Resources struct {
			DeploymentPolicy struct {
				Properties struct {
					// This policy document will be converted to TF json
					PolicyDocument map[string]interface{}
				}
			}
		}
	}

	// Parse CF deployment role
	var cfn template
	srcPath := filepath.Join("deployments", "auxiliary", "cloudformation", "panther-deployment-role.yml")
	if err := util.ParseTemplate(srcPath, &cfn); err != nil {
		return err
	}

	doc := cfn.Resources.DeploymentPolicy.Properties.PolicyDocument
	if len(doc) == 0 {
		return fmt.Errorf("%s: Resources.DeploymentPolicy.Properties.PolicyDocument is empty", srcPath)
	}

	// Convert to TF and marshal to JSON string
	policy := convertPolicyToTf(doc)
	// json stdlib handles pretty-print (indentation) better than jsoniter
	policyText, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal failed: %v", err)
	}

	// Replace EOT block in TF file.
	dstPath := filepath.Join("deployments", "auxiliary", "terraform", "panther_deployment_role", "main.tf")
	tf := util.MustReadFile(dstPath)
	pattern := regexp.MustCompile(`<<EOT(.|\n)+?EOT`)
	tf = pattern.ReplaceAll(tf, []byte("<<EOT\n"+string(policyText)+"\nEOT"))
	util.MustWriteFile(dstPath, tf)

	return nil
}

// Update CloudFormation IAM policy document to be Terraform compatible.
//
// Specifically, replace Fn::Sub with TF interpolation. For example,
//     { "Fn::Sub": "arn:${AWS::Partition}:firehose:*:${AWS::AccountId}:deliverystream/panther-*" }
// becomes
//     "arn:${var.aws_partition}:firehose:*:${var.aws_account_id}:deliverystream/panther-*"
func convertPolicyToTf(doc interface{}) interface{} {
	switch doc := doc.(type) {
	case map[string]interface{}:
		if len(doc) == 1 {
			if val, ok := doc["Fn::Sub"]; ok {
				// Remove Sub key and use the interpolated string value
				return convertPolicyToTf(val)
			}

			// Other functions like !Ref or !FindInMap are not supported here
			// (and should not be present in the deployment role).
			panic(fmt.Errorf("unexpected singleton map: %v", doc))
		}

		result := make(map[string]interface{}, len(doc))
		for key, val := range doc {
			result[key] = convertPolicyToTf(val)
		}
		return result

	case []interface{}:
		result := make([]interface{}, 0, len(doc))
		for _, item := range doc {
			result = append(result, convertPolicyToTf(item))
		}
		return result

	case string:
		// Convert AWS pseudo-parameters into Terraform interpolation strings
		result := strings.ReplaceAll(doc, "${AWS::Partition}", "${var.aws_partition}")
		return strings.ReplaceAll(result, "${AWS::AccountId}", "${var.aws_account_id}")

	default:
		return doc
	}
}
