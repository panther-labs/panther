package mage

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
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
)

const (
	ecrRepoName    = "panther-web"
	ecsClusterName = "panther-web-cluster"
	ecsServiceName = "panther-web"

	// Upper bound on the number of s3 object versions we'll delete manually.
	s3MaxDeletes = 10000
)

type deleteStackResult struct {
	stackName string
	err       error
}

// Log the results of a delete stack request
func (r deleteStackResult) log() {
	if r.err != nil {
		logger.Fatalf("stack %s failed to delete: %v", r.stackName, r.err)
	}
	logger.Infof("%s successfully deleted", r.stackName)
}

// Teardown Destroy all Panther infrastructure
func Teardown() {
	awsSession := teardownConfirmation()

	// Some resources must be destroyed directly before deleting their parent CFN stacks.
	destroyEcrRepo(awsSession)
	stopEcsService(awsSession)

	// Delete all CloudFormation stacks in parallel.
	destroyCfnStacks(awsSession)

	// All S3 buckets have "DeletionPolicy: Retain" so as to not block CFN stack deletion.
	// In other words, CloudFormation will not delete S3 buckets - we do so here.
	destroyPantherBuckets(awsSession)

	// Remove self-signed certs that may have been uploaded if they are no longer in use.
	destroyAcmCerts(awsSession)

	// It's possible to have buffered Lambda logs written shortly after the stacks were deleted.
	destroyLogGroups(awsSession)

	logger.Info("successfully removed Panther infrastructure")
}

func teardownConfirmation() *session.Session {
	// Check the AWS account ID
	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}
	identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		logger.Fatalf("failed to get caller identity: %v", err)
	}

	logger.Warnf("Teardown will destroy all Panther infrastructure in account %s (%s)",
		*identity.Account, *awsSession.Config.Region)
	result := promptUser("Are you sure you want to continue? (yes|no) ", nonemptyValidator)
	if strings.ToLower(result) != "yes" {
		logger.Fatal("teardown aborted")
	}

	return awsSession
}

// Remove the ECR repo and all of its images
func destroyEcrRepo(awsSession *session.Session) {
	logger.Infof("removing ECR repository %s", ecrRepoName)
	client := ecr.New(awsSession)
	_, err := client.DeleteRepository(&ecr.DeleteRepositoryInput{
		Force:          aws.Bool(true), // remove images as well
		RepositoryName: aws.String(ecrRepoName),
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "RepositoryNotFoundException" {
			// repo doesn't exist - that's fine, nothing to do here
			return
		}
		logger.Fatalf("failed to delete ECR repository: %v", err)
	}
}

// Stop the web ECS service so CloudFormation can delete the ECS cluster
func stopEcsService(awsSession *session.Session) {
	client := ecs.New(awsSession)

	logger.Infof("stopping ECS service %s in cluster %s", ecsServiceName, ecsClusterName)
	_, err := client.DeleteService(&ecs.DeleteServiceInput{
		Cluster: aws.String(ecsClusterName),
		Force:   aws.Bool(true), // stop running tasks as well
		Service: aws.String(ecsServiceName),
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ClusterNotFoundException" {
			return // cluster does not exist
		}
		logger.Fatalf("failed to delete ECS service: %v", err)
	}

	waitInput := &ecs.DescribeServicesInput{
		Cluster:  aws.String(ecsClusterName),
		Services: []*string{aws.String(ecsServiceName)},
	}
	if err = client.WaitUntilServicesInactive(waitInput); err != nil {
		logger.Fatalf("ECS service %s did not stop successfully: %v", ecsServiceName, err)
	}
}

// Destroy CloudFormation stacks in parallel
func destroyCfnStacks(awsSession *session.Session) {
	results := make(chan deleteStackResult)
	client := cloudformation.New(awsSession)
	stacks := []string{backendStack, bucketStack, monitoringStack, frontendStack, databasesStack}

	// Trigger the deletion of each stack
	logger.Infof("deleting CloudFormation stacks: %s", strings.Join(stacks, ", "))
	for _, stack := range stacks {
		go deleteStack(client, aws.String(stack), results)
	}

	// Wait for all of the stacks to finish
	for range stacks {
		(<-results).log()
	}
}

// Delete a single CFN stack and wait for it to finish
func deleteStack(client *cloudformation.CloudFormation, stack *string, results chan deleteStackResult) {
	if _, err := client.DeleteStack(&cloudformation.DeleteStackInput{StackName: stack}); err != nil {
		results <- deleteStackResult{stackName: *stack, err: err}
		return
	}

	if err := client.WaitUntilStackDeleteComplete(&cloudformation.DescribeStacksInput{StackName: stack}); err != nil {
		// The stack reached DELETE_FAILED instead of DELETE_COMPLETE status, the 'err' variable is not helpful.
		// TODO - describe the stack and its resources to find the reason(s) for the failure
		results <- deleteStackResult{stackName: *stack, err: fmt.Errorf("stack %s failed to delete", *stack)}
		return
	}

	results <- deleteStackResult{stackName: *stack}
}

// Delete all objects in an S3 bucket and then remove it.
//
// Only buckets prefixed with "panther-" AND tagged with "Application:Panther" will be removed.
func destroyPantherBuckets(awsSession *session.Session) {
	client := s3.New(awsSession)
	logger.Debug("checking for panther s3 buckets")
	list, err := client.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		logger.Fatalf("failed to list s3 buckets: %v", err)
	}

	for _, bucket := range list.Buckets {
		if !strings.HasPrefix(*bucket.Name, "panther-") {
			continue
		}

		// To be extra safe, verify the tags as well.
		tagging, err := client.GetBucketTagging(&s3.GetBucketTaggingInput{Bucket: bucket.Name})
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && (awsErr.Code() == "BucketRegionError" || awsErr.Code() == "NoSuchBucket") {
				// this bucket does not exist in the same region as our client: skip it
				continue
			}
			logger.Fatalf("failed to get tags for s3://%s: %v", *bucket.Name, err)
		}

		foundTag := false
		for _, tag := range tagging.TagSet {
			if aws.StringValue(tag.Key) == "Application" && aws.StringValue(tag.Value) == "Panther" {
				removeBucket(client, bucket.Name)
				foundTag = true
				break
			}
		}

		if !foundTag {
			logger.Warnf("skipping s3 bucket %s: no 'Application=Panther' tag found", *bucket.Name)
		}
	}
}

// Empty, then delete the given S3 bucket.
//
// Or, if there are too many objects to delete directly, set an expiration lifecycle policy instead.
func removeBucket(client *s3.S3, bucketName *string) {
	input := &s3.ListObjectVersionsInput{Bucket: bucketName}
	var objectVersions []*s3.ObjectIdentifier

	// List all object versions (including delete markers)
	err := client.ListObjectVersionsPages(input, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
		for _, marker := range page.DeleteMarkers {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: marker.Key, VersionId: marker.VersionId})
		}

		for _, version := range page.Versions {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: version.Key, VersionId: version.VersionId})
		}

		// Keep paging as long as we don't have too many items yet
		return len(objectVersions) < s3MaxDeletes
	})
	if err != nil {
		logger.Fatalf("failed to list object versions for %s: %v", *bucketName, err)
	}

	if len(objectVersions) >= s3MaxDeletes {
		logger.Warnf("s3://%s has too many items to delete directly, setting an expiration policy instead", *bucketName)
		_, err = client.PutBucketLifecycleConfiguration(&s3.PutBucketLifecycleConfigurationInput{
			Bucket: bucketName,
			LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
				Rules: []*s3.LifecycleRule{
					{
						AbortIncompleteMultipartUpload: &s3.AbortIncompleteMultipartUpload{
							DaysAfterInitiation: aws.Int64(1),
						},
						Expiration: &s3.LifecycleExpiration{
							Days: aws.Int64(1),
						},
						Filter: &s3.LifecycleRuleFilter{
							Prefix: aws.String(""), // empty prefix required to apply rule to all objects
						},
						ID: aws.String("panther-expire-everything"),
						NoncurrentVersionExpiration: &s3.NoncurrentVersionExpiration{
							NoncurrentDays: aws.Int64(1),
						},
						Status: aws.String("Enabled"),
					},
				},
			},
		})
		if err != nil {
			logger.Fatalf("failed to set expiration policy for %s: %v", *bucketName, err)
		}
		return
	}

	// Here there aren't too many objects, we can delete them in a handful of BatchDelete calls.
	logger.Infof("deleting s3://%s", *bucketName)
	err = s3batch.DeleteObjects(client, 2*time.Minute, &s3.DeleteObjectsInput{
		Bucket: bucketName,
		Delete: &s3.Delete{Objects: objectVersions},
	})
	if err != nil {
		logger.Fatalf("failed to batch delete objects: %v", err)
	}

	if _, err = client.DeleteBucket(&s3.DeleteBucketInput{Bucket: bucketName}); err != nil {
		logger.Fatalf("failed to delete bucket %s: %v", *bucketName, err)
	}
}

// Destroy self-signed Panther ACM certificates.
//
// Only certs for "example.com" tagged with "Application:Panther" and not currently in use will be deleted.
func destroyAcmCerts(awsSession *session.Session) {
	logger.Debug("checking for ACM certificates")
	client := acm.New(awsSession)

	err := client.ListCertificatesPages(&acm.ListCertificatesInput{}, func(page *acm.ListCertificatesOutput, lastPage bool) bool {
		for _, summary := range page.CertificateSummaryList {
			if aws.StringValue(summary.DomainName) == "example.com" {
				safeRemoveCert(client, summary.CertificateArn)
			}
		}
		return true
	})
	if err != nil {
		logger.Fatalf("failed to list ACM certificates: %v", err)
	}
}

// Remove an ACM cert if it's tagged with Panther and not in use.
func safeRemoveCert(client *acm.ACM, arn *string) {
	tags, err := client.ListTagsForCertificate(&acm.ListTagsForCertificateInput{CertificateArn: arn})
	if err != nil {
		logger.Fatalf("failed to list tags for ACM cert %s: %v", *arn, err)
	}

	for _, tag := range tags.Tags {
		if aws.StringValue(tag.Key) == "Application" && aws.StringValue(tag.Value) == "Panther" {
			cert, err := client.DescribeCertificate(&acm.DescribeCertificateInput{CertificateArn: arn})
			if err != nil {
				logger.Fatalf("failed to describe ACM cert %s: %v", *arn, err)
			}

			if len(cert.Certificate.InUseBy) > 0 {
				logger.Warnf("skipping ACM cert %s, which is tagged with Panther but currently in use", *arn)
				return
			}

			logger.Infof("deleting ACM cert %s", *arn)
			if _, err = client.DeleteCertificate(&acm.DeleteCertificateInput{CertificateArn: arn}); err != nil {
				logger.Fatalf("failed to delete cert %s: %v", *arn, err)
			}
			return
		}
	}

	// This cert is not tagged with Panther, ignore it
}

// Destroy any leftover /aws/lambda/panther- log groups
func destroyLogGroups(awsSession *session.Session) {
	logger.Debug("checking for leftover Panther log groups")
	client := cloudwatchlogs.New(awsSession)
	input := &cloudwatchlogs.DescribeLogGroupsInput{LogGroupNamePrefix: aws.String("/aws/lambda/panther-")}

	err := client.DescribeLogGroupsPages(input, func(page *cloudwatchlogs.DescribeLogGroupsOutput, lastPage bool) bool {
		for _, group := range page.LogGroups {
			logger.Infof("deleting CloudWatch log group %s", *group.LogGroupName)
			_, err := client.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{LogGroupName: group.LogGroupName})
			if err != nil {
				logger.Fatalf("failed to delete log group %s: %v", *group.LogGroupName, err)
			}
		}
		return true // keep paging
	})
	if err != nil {
		logger.Fatalf("failed to list log groups: %v", err)
	}
}
