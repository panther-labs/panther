package master

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
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Packaging configuration
type packager struct {
	// zap logger for printing progress updates
	log *zap.SugaredLogger

	// AWS region where the S3 bucket lives
	region string

	// S3 bucket for uploading lambda zipfiles
	bucket string

	// Worker build/pkg routines running for each template.
	//
	// Because nested templates trigger recursive packaging, the _total_ number of workers
	// running will reach numWorkers^2 (but the workers in the root stack won't be doing anything
	// until the children are finished).
	numWorkers int
}

// Key-Value information for each CloudFormation resource passed to the workers
type cfnResource struct {
	// Map key in Resources section of CFN template, e.g. "Bootstrap"
	logicalID string

	// Map values, e.g. {"Type": "AWS::CloudFormation::Stack", "Properties": {...}}
	fields map[string]interface{}

	// Error returned by the worker
	err error
}

// TODO - expose a 'mage pkg' command?
// Recursively package assets in a CFN template, uploading local filepaths to S3.
//
// This offers essentially the same functionality as 'sam package' or 'aws cloudformation package',
// but parallelized and compiled directly into mage for faster, simpler deployments.
//
// Supports the following resource types:
//     AWS::AppSync::GraphQLSchema (DefinitionS3Location)
//     AWS::CloudFormation::Stack (TemplateURL)
//     AWS::Lambda::LayerVersion (Content)
//     AWS::Serverless::Function (CodeUri)
//     TODO - ECS service?
//
// Returns the path to the packaged template (in the out/ folder)
func (p packager) template(path string) (string, error) {
	// We considered parsing templates with https://github.com/awslabs/goformation, but
	// it doesn't support all intrinsic functions and it tries to actually resolve parameters.
	// We just need an exact representation of the yml structure; a map[string]interface{} is the
	// safest approach because we can access just the keys we care about and leave the rest alone.
	var body map[string]interface{}
	if err := util.ParseTemplate(path, &body); err != nil {
		return "", err
	}

	// Start the worker routines
	resources := body["Resources"].(map[string]interface{})
	jobs := make(chan cfnResource, len(resources))
	results := make(chan cfnResource, len(resources))
	for w := 1; w <= p.numWorkers; w++ {
		go p.resourceWorker(path, w, jobs, results)
	}

	// Queue a job for each resource in the template
	for logicalID, r := range resources {
		jobs <- cfnResource{logicalID: logicalID, fields: r.(map[string]interface{})}
	}
	close(jobs)

	// Rebuild the resource map with the packaged versions
	for i := 0; i < len(resources); i++ {
		result := <-results
		if result.err != nil {
			return "", fmt.Errorf("%s packaging failed: %s: %s", path, result.logicalID, result.err)
		}
		resources[result.logicalID] = result.fields
	}

	// Write the packaged template to out/deployments
	newBody, err := yaml.Marshal(body)
	if err != nil {
		return "", err
	}

	pkgPath := filepath.Join("out", "deployments", "pkg."+filepath.Base(path))
	if err = os.MkdirAll(filepath.Dir(pkgPath), 0700); err != nil {
		return "", err
	}
	if err = ioutil.WriteFile(pkgPath, newBody, 0600); err != nil {
		return "", err
	}

	p.log.Infof("finished packaging %s to %s", path, pkgPath)
	return pkgPath, nil
}

// Each of the build/pkg workers runs this loop, processing one CloudFormation resource at a time.
// TODO - consider triggering the go + docker build from here rather than walking source tree
func (p packager) resourceWorker(path string, id int, resources chan cfnResource, results chan cfnResource) {
	for r := range resources {
		rType := r.fields["Type"].(string)

		switch rType {
		case "AWS::AppSync::GraphQLSchema":
			results <- r // TODO

		case "AWS::CloudFormation::Stack":
			p.log.Debugf("[%d] %s: packaging %s %s", id, path, rType, r.logicalID)
			properties := r.fields["Properties"].(map[string]interface{})
			nestedPath := properties["TemplateURL"].(string)
			if strings.HasPrefix(nestedPath, "https://") {
				break // template URL is already an S3 path
			}

			// Recursively package the nested stack
			pkgPath, err := p.template(filepath.Join("deployments", nestedPath))
			if err != nil {
				r.err = err
				break
			}

			// Upload packaged template to S3
			s3Key, _, err := deploy.UploadAsset(p.log, pkgPath, p.bucket)
			if err != nil {
				r.err = err
				break
			}

			properties["TemplateURL"] = fmt.Sprintf(
				"https://s3.%s.amazonaws.com/%s/%s", p.region, p.bucket, s3Key)

		case "AWS::Lambda::LayerVersion":
			break // TODO

		case "AWS::Serverless::Function":
			break // TODO
		}

		results <- r
	}
}
