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
	"bytes"
	"context"
	"crypto/sha1" // nolint: gosec
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Max number of worker build/pkg routines running for each template.
//
// Because nested templates trigger recursive packaging, the _total_ number of workers
// running will reach about NumWorkers^2
// (but the workers in the root stack won't be doing anything until the children are finished).
const numWorkers = 4

// Packaging configuration
type Packager struct {
	// zap logger for printing progress updates
	Log *zap.SugaredLogger

	// AWS session configuration
	AwsConfig aws.Config

	// S3 bucket for uploading lambda zipfiles
	Bucket string

	// The image ID (truncated SHA256) for the "docker push" command.
	//
	// The docker image must be built before the packaging starts.
	DockerImageID string

	// ECR registry URI for publishing docker images
	EcrRegistry string

	// If true, docker images in ECR will be tagged with their hash and duplicate images
	// will not be uploaded - this is optimized for development.
	//
	// If false, the docker images will be tagged with the Panther version (for releases),
	// and it will push to ECR even if it means overwriting an image with the same tag.
	EcrTagWithHash bool

	// Pip library versions to install for the shared python layer
	PipLibs []string

	// Optional additional processing after the packaging and yaml marshal but before writing
	// the final template to disk.
	//
	// The function should return the modified template body.
	PostProcess func(originalPath string, packagedBody []byte) []byte
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
func (p *Packager) Template(path string) (string, error) {
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
	defer close(jobs)
	results := make(chan cfnResource, len(resources))
	defer close(results)

	workers := numWorkers
	if len(resources) < workers {
		// Some stacks have very few resources (e.g. aux templates);
		// no need to spin up workers that won't have anything to do.
		workers = len(resources)
	}
	p.Log.Debugf("packaging %s: starting %d workers", path, workers)
	for w := 1; w <= workers; w++ {
		go p.resourceWorker(jobs, results)
	}

	// Queue a job for each resource in the template
	for logicalID, r := range resources {
		jobs <- cfnResource{logicalID: logicalID, fields: r.(map[string]interface{})}
	}

	// Rebuild the resource map with the packaged versions
	for i := 0; i < len(resources); i++ {
		result := <-results
		if result.err != nil {
			return "", fmt.Errorf("%s packaging failed: %s: %s", path, result.logicalID, result.err)
		}
		resources[result.logicalID] = result.fields
	}

	// Write the packaged template to out/deployments
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2) // 2 spaces instead of 4 for a smaller template body
	if err := enc.Encode(body); err != nil {
		return "", err
	}
	newBody := buf.Bytes()

	if p.PostProcess != nil {
		newBody = p.PostProcess(path, newBody)
	}

	pkgPath := filepath.Join("out", "deployments", "pkg."+filepath.Base(path))
	if err := os.MkdirAll(filepath.Dir(pkgPath), 0700); err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(pkgPath, newBody, 0600); err != nil {
		return "", err
	}

	p.Log.Infof("packaged %s", pkgPath)
	return pkgPath, nil
}

// Each of the build/pkg workers runs this loop, processing one CloudFormation resource at a time.
func (p *Packager) resourceWorker(resources <-chan cfnResource, results chan<- cfnResource) {
	for r := range resources {
		switch r.fields["Type"].(string) {
		case "AWS::AppSync::GraphQLSchema":
			results <- p.appsyncGraphQlSchema(r)
		case "AWS::CloudFormation::Stack":
			results <- p.cloudformationStack(r)
		case "AWS::ECS::TaskDefinition":
			// We assume there is only one of these in Panther
			results <- p.ecsTaskDefinition(r)
		case "AWS::Lambda::LayerVersion":
			// We assume there is only one of these in Panther
			results <- p.lambdaLayerVersion(r)
		case "AWS::Serverless::Function":
			results <- p.serverlessFunction(r)
		default:
			results <- r
		}
	}
}

// Upload AppSync GraphQL schema to S3 - returns resource with modified DefinitionS3Location property
func (p *Packager) appsyncGraphQlSchema(r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	schemaPath := properties["DefinitionS3Location"].(string)
	if strings.HasPrefix(schemaPath, "s3://") {
		return r // already an S3 path
	}

	// Upload schema to S3
	p.Log.Debugf("packaging AWS::Appsync::GraphQLSchema %s", r.logicalID)
	s3Key, _, err := p.UploadAsset(filepath.Join("deployments", schemaPath), "")
	if err != nil {
		r.err = err
		return r
	}

	properties["DefinitionS3Location"] = util.S3URI(p.Bucket, s3Key)
	return r
}

// Upload nested CFN template to S3 - returns resource with modified TemplateURL property
func (p *Packager) cloudformationStack(r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	nestedPath := properties["TemplateURL"].(string)
	if strings.HasPrefix(nestedPath, "https://") {
		return r // template URL is already an S3 path
	}

	// Recursively package the nested stack
	p.Log.Debugf("packaging AWS::CloudFormation::Stack %s", r.logicalID)
	pkgPath, err := p.Template(filepath.Join("deployments", nestedPath))
	if err != nil {
		r.err = err
		return r
	}

	// Upload packaged template to S3
	s3Key, _, err := p.UploadAsset(pkgPath, "")
	if err != nil {
		r.err = err
		return r
	}

	properties["TemplateURL"] = util.S3ObjectURL(p.AwsConfig.Region, p.Bucket, s3Key)
	return r
}

// Upload web docker image to ECR - returns resource with modified Image property
func (p *Packager) ecsTaskDefinition(r cfnResource) cfnResource {
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

	p.Log.Debugf("packaging AWS::ECS::TaskDefinition %s", r.logicalID)

	var tag string

	if p.EcrTagWithHash {
		// Check if this image ID already exists in ECR before uploading it
		response, err := ecr.NewFromConfig(p.AwsConfig).DescribeImages(context.TODO(), &ecr.DescribeImagesInput{
			ImageIds:       []ecrTypes.ImageIdentifier{{ImageTag: &p.DockerImageID}},
			RepositoryName: aws.String(strings.Split(p.EcrRegistry, "/")[1]),
		})
		if err == nil && len(response.ImageDetails) > 0 {
			p.Log.Debugf("ecr image tag %s already exists", p.DockerImageID)
			containerDef["Image"] = p.EcrRegistry + ":" + p.DockerImageID
			return r
		}

		var notFound *ecrTypes.ImageNotFoundException
		if err != nil && !errors.As(err, &notFound) {
			// we couldn't actually check the image status - fallback to the docker push
			p.Log.Warnf("failed to check for existing ecr image: %s", err)
		}
	} else {
		// Images will be tagged with the panther version
		tag = util.Semver()
	}

	// Either the img does not yet exist or the caller requested release tagging - docker push to ECR
	containerDef["Image"], r.err = p.DockerPush(tag)
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
func (p *Packager) lambdaLayerVersion(r cfnResource) cfnResource {
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

	p.Log.Debugf("packaging AWS::Lambda::LayerVersion %s", r.logicalID)

	if err := build.Layer(p.Log, p.PipLibs); err != nil {
		r.err = err
		return r
	}

	// Upload layer zipfile to S3
	s3Key, _, err := p.UploadAsset(filepath.Join("deployments", content), "")
	if err != nil {
		r.err = err
		return r
	}

	properties["Content"] = map[string]string{"S3Bucket": p.Bucket, "S3Key": s3Key}
	return r
}

// Compile lambda zipfile and upload to S3 - returns resource with modified CodeUri property
func (p *Packager) serverlessFunction(r cfnResource) cfnResource {
	properties := r.fields["Properties"].(map[string]interface{})
	codeURI := properties["CodeUri"].(string)
	if strings.HasPrefix(codeURI, "s3://") {
		return r // codeURI is already an S3 path
	}

	p.Log.Debugf("packaging AWS::Serverless::Function %s", r.logicalID)

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
	s3Key, _, err := p.UploadAsset(zipPath, "")
	if err != nil {
		r.err = err
		return r
	}

	properties["CodeUri"] = util.S3URI(p.Bucket, s3Key)
	return r
}

// Upload a CloudFormation asset to S3, returning s3 object key and version.
//
// If no s3 key is chosen by the caller, the hash is used for the key and objects
// will not be uploaded if they already exist.
func (p *Packager) UploadAsset(assetPath, s3Key string) (string, string, error) {
	// Assets can be up to 50 MB or so, they all should fit in memory just fine
	contents, err := ioutil.ReadFile(assetPath)
	if err != nil {
		return "", "", err
	}

	s3Client := s3.NewFromConfig(p.AwsConfig)

	if s3Key == "" {
		// We are using SHA1 for caching / asset lookup, we don't need strong cryptographic guarantees
		// (SHA1 is faster than SHA256)
		s3Key = fmt.Sprintf("%x", sha1.Sum(contents)) // nolint: gosec

		head, err := s3Client.HeadObject(context.TODO(),
			&s3.HeadObjectInput{Bucket: &p.Bucket, Key: &s3Key})
		if err == nil {
			p.Log.Debugf("upload: %s (sha1:%s) already exists in %s", assetPath, s3Key[:10], p.Bucket)
			return s3Key, *head.VersionId, nil // object already exists in S3 with the same hash
		}
	}

	p.Log.Infof("uploading %s file %s to S3: %s",
		util.ByteCountSI(int64(len(contents))), assetPath, s3Key[:12])

	response, err := manager.NewUploader(s3Client).Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: &p.Bucket,
		Key:    &s3Key,
		Body:   bytes.NewReader(contents),
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to upload %s: %s", assetPath, err)
	}
	return s3Key, *response.VersionID, nil
}
