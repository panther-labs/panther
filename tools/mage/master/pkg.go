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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ecr"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Packaging configuration
type packager struct {
	// zap logger for printing progress updates
	log *zap.SugaredLogger

	// AWS region where assets will be uploaded (S3 bucket / ECR region)
	region string

	// S3 bucket for uploading lambda zipfiles
	bucket string

	// ECR registry URI for publishing docker images
	ecrRegistry string

	// If true, docker images in ECR will be tagged with their hash, and duplicate images
	// will not be uploaded - this is optimized for development.
	//
	// If false, the docker images will be tagged with the Panther version (for releases),
	// and it will push to ECR even if it means overwriting an image with the same tag.
	ecrTagWithHash bool

	// Pip libraries to pip install for the shared python layer
	pipLibs []string

	// Max number of worker build/pkg routines running for each template.
	//
	// Because nested templates trigger recursive packaging, the _total_ number of workers
	// running will reach about numWorkers^2
	// (but the workers in the root stack won't be doing anything until the children are finished).
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

// Recursively build package assets in a CFN template to S3 and ECR
//
// This offers similar functionality to 'sam package' or 'aws cloudformation package',
// but parallelized and compiled directly into mage for faster, simpler deployments.
//
// The build operations (go build, docker build, pip install, etc) are pushed down to the
// packaging handlers instead of running at the beginning of the deploy process.
// In other words, assets are built "just-in-time" before they are uploaded.
// This way, we get parallel builds with a good balance of network and CPU operations,
// and we build only the exact set of assets we need for each stack.
//
// Supports the following resource types:
//     AWS::AppSync::GraphQLSchema (DefinitionS3Location)
//     AWS::CloudFormation::Stack (TemplateURL)
//     AWS::ECS::TaskDefinition (Image)
//     AWS::Lambda::LayerVersion (Content)
//     AWS::Serverless::Function (CodeUri)
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

	workers := p.numWorkers
	if len(resources) < workers {
		// Some stacks have very few resources (e.g. aux templates);
		// no need to spin up workers that won't have anything to do.
		workers = len(resources)
	}
	for w := 1; w <= workers; w++ {
		go p.resourceWorker(fmt.Sprintf("[%d] %s", w, path), jobs, results)
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

	p.log.Infof("packaged %s", pkgPath)
	return pkgPath, nil
}

// Each of the build/pkg workers runs this loop, processing one CloudFormation resource at a time.
func (p packager) resourceWorker(logPrefix string, resources <-chan cfnResource, results chan<- cfnResource) {
	for r := range resources {
		rType := r.fields["Type"].(string)

		switch rType {
		case "AWS::AppSync::GraphQLSchema":
			results <- p.appsyncGraphQlSchema(logPrefix, r)
		case "AWS::CloudFormation::Stack":
			results <- p.cloudformationStack(logPrefix, r)
		case "AWS::ECS::TaskDefinition":
			// We assume only one of these in Panther
			results <- p.ecsTaskDefinition(logPrefix, r)
		case "AWS::Lambda::LayerVersion":
			// We assume only one of these in Panther
			results <- p.lambdaLayerVersion(logPrefix, r)
		case "AWS::Serverless::Function":
			results <- p.serverlessFunction(logPrefix, r)
		default:
			results <- r
		}
	}
}

// Upload AppSync GraphQL schema to S3 - returns resource with modified DefinitionS3Location property
func (p packager) appsyncGraphQlSchema(logPrefix string, r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	schemaPath := properties["DefinitionS3Location"].(string)
	if strings.HasPrefix(schemaPath, "s3://") {
		return r // already an S3 path
	}

	// Upload schema to S3
	p.log.Debugf("%s: packaging AWS::Appsync::GraphQLSchema %s", logPrefix, r.logicalID)
	s3Key, _, err := deploy.UploadAsset(p.log, filepath.Join("deployments", schemaPath), p.bucket)
	if err != nil {
		r.err = err
		return r
	}

	properties["DefinitionS3Location"] = fmt.Sprintf("s3://%s/%s", p.bucket, s3Key)
	return r
}

// Upload nested CFN template to S3 - returns resource with modified TemplateURL property
func (p packager) cloudformationStack(logPrefix string, r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	nestedPath := properties["TemplateURL"].(string)
	if strings.HasPrefix(nestedPath, "https://") {
		return r // template URL is already an S3 path
	}

	// Recursively package the nested stack
	p.log.Debugf("%s: packaging AWS::CloudFormation::Stack %s", logPrefix, r.logicalID)
	pkgPath, err := p.template(filepath.Join("deployments", nestedPath))
	if err != nil {
		r.err = err
		return r
	}

	// Upload packaged template to S3
	s3Key, _, err := deploy.UploadAsset(p.log, pkgPath, p.bucket)
	if err != nil {
		r.err = err
		return r
	}

	properties["TemplateURL"] = fmt.Sprintf(
		"https://s3.%s.amazonaws.com/%s/%s", p.region, p.bucket, s3Key)
	return r
}

// Upload web docker image to ECR - returns resource with modified Image property
func (p packager) ecsTaskDefinition(logPrefix string, r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	containerDefs := properties["ContainerDefinitions"].([]interface{})
	if len(containerDefs) != 1 {
		r.err = fmt.Errorf("expected 1 ContainerDefinition, found %d", len(containerDefs))
	}

	containerDef := containerDefs[0].(map[string]interface{})
	dockerfile := containerDef["Image"].(string)
	if strings.Contains(dockerfile, ".dkr.ecr.") {
		return r // Image is already an ECR url
	}

	p.log.Debugf("%s: packaging AWS::ECS::TaskDefinition %s", logPrefix, r.logicalID)

	imageID, err := deploy.DockerBuild(filepath.Join("deployments", dockerfile))
	if err != nil {
		r.err = err
		return r
	}

	ecrClient := clients.ECR()
	var tag string

	if p.ecrTagWithHash {
		// Check if this image ID already exists in ECR before uploading it
		response, err := ecrClient.DescribeImages(&ecr.DescribeImagesInput{
			ImageIds:       []*ecr.ImageIdentifier{{ImageTag: &imageID}},
			RepositoryName: aws.String(strings.Split(p.ecrRegistry, "/")[1]),
		})
		if err == nil && len(response.ImageDetails) > 0 {
			p.log.Debugf("%s: ecr image tag %s already exists", logPrefix, imageID)
			containerDef["Image"] = p.ecrRegistry + ":" + imageID
			return r
		}

		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == ecr.ErrCodeImageNotFoundException {
			// image doesn't exist - continue to the docker push below
		} else {
			// we couldn't actually check the image status - fallback to the docker push
			p.log.Warnf("%s: failed to check for existing ecr image: %s", logPrefix, err)
		}
	} else {
		// Images will be tagged with the panther version
		tag = util.Semver()
	}

	// Either the img does not yet exist or the caller requested release tagging - docker push to ECR
	containerDef["Image"], r.err = deploy.DockerPush(ecrClient, p.ecrRegistry, imageID, tag)
	return r
}

// Build the shared pip layer (there is only LayerVersion resource today)
//
//   Content: ../out/layer.zip
//
// will be replaced with
//
//   Content:
//     S3Bucket: panther-dev-...
//     S3Key: abcd...
func (p packager) lambdaLayerVersion(logPrefix string, r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	content, ok := properties["Content"].(string)
	if !ok {
		return r // Content is already an object (referencing S3)
	}

	// We only have one pre-built layer today, and that's not likely to change anytime soon.
	if r.logicalID != "PythonLayer" {
		r.err = fmt.Errorf("unexpected LayerVersion %s: wanted only bootstrap_gateway/PythonLayer",
			r.logicalID)
		return r
	}

	p.log.Debugf("%s: packaging AWS::Lambda::LayerVersion %s", logPrefix, r.logicalID)

	if err := build.Layer(p.log, p.pipLibs); err != nil {
		r.err = err
		return r
	}

	// Upload layer zipfile to S3
	s3Key, _, err := deploy.UploadAsset(p.log, filepath.Join("deployments", content), p.bucket)
	if err != nil {
		r.err = err
		return r
	}

	properties["Content"] = map[string]string{"S3Bucket": p.bucket, "S3Key": s3Key}
	return r
}

// Compile lambda zipfile and upload to S3 - returns resource with modified CodeUri property
func (p packager) serverlessFunction(logPrefix string, r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	codeURI := properties["CodeUri"].(string)
	if strings.HasPrefix(codeURI, "s3://") {
		return r // codeURI is already an S3 path
	}

	p.log.Debugf("%s: packaging AWS::Serverless::Function %s", logPrefix, r.logicalID)

	// Build/find the directory which needs to be zipped
	var zipDir string
	if properties["Runtime"].(string) == "go1.x" {
		// compile Go binary
		bin, err := build.LambdaPackage(filepath.Join("deployments", codeURI))
		if err != nil {
			r.err = err
			return r
		}

		// bin path looks like "out/bin/core/custom_resources/main"
		zipDir = filepath.Dir(bin)
	} else {
		// python functions zip the entire codeURI directory
		zipDir = filepath.Join("deployments", codeURI)
	}

	fnName := properties["FunctionName"].(string)
	zipPath := filepath.Join("out", "lambda", fnName+".zip")
	if err := shutil.ZipDirectory(zipDir, zipPath, false); err != nil {
		r.err = err
		return r
	}

	// Upload lambda deployment pkg to S3
	s3Key, _, err := deploy.UploadAsset(p.log, zipPath, p.bucket)
	if err != nil {
		r.err = err
		return r
	}

	properties["CodeUri"] = fmt.Sprintf("s3://%s/%s", p.bucket, s3Key)
	return r
}
