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
	"strings"

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

	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	ecrRepoName    = "panther-web"
	ecsClusterName = "panther-web-cluster"
	ecsServiceName = "panther-web"
)

var (
	// All stacks except the prerequisite buckets stack can be deleted in parallel.
	deleteStacksParallel = []string{monitoringStack, frontendStack, databasesStack, backendStack}
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
	destroyPantherBuckets(awsSession)
	destroyEcrRepo(awsSession)
	destroyEcsCluster(awsSession)

	destroyCfnStacks(awsSession)

	// Remove self-signed certs that may have been uploaded if they are no longer in use.
	destroyAcmCerts(awsSession)

	// It's possible to have buffered Lambda logs written shortly after the stacks were deleted.
	destroyLogGroups(awsSession)

	logger.Info("successfully removed all Panther infrastructure")
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

	logger.Warnf("THIS WILL DESTROY ALL PANTHER INFRASTRUCTURE IN AWS ACCOUNT %s (%s)",
		*identity.Account, *awsSession.Config.Region)
	result := promptUser("Are you sure you want to continue? (yes|no) ", nonemptyValidator)
	if strings.ToLower(result) != "yes" {
		logger.Fatal("permission denied: teardown canceled")
	}

	return awsSession
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
				removeBucket(awsSession, client, bucket.Name)
				foundTag = true
				break
			}
		}

		if !foundTag {
			logger.Warnf("skipping s3 bucket %s: no 'Application=Panther' tag found", *bucket.Name)
		}
	}
}

// Empty, then delete the given S3 bucket
func removeBucket(awsSession *session.Session, client *s3.S3, bucketName *string) {
	logger.Infof("removing s3://%s", *bucketName)
	if err := testutils.ClearS3Bucket(awsSession, *bucketName); err != nil {
		logger.Fatalf("failed to empty bucket %s: %v", *bucketName, err)
	}

	if _, err := client.DeleteBucket(&s3.DeleteBucketInput{Bucket: bucketName}); err != nil {
		logger.Fatalf("failed to delete bucket %s: %v", *bucketName, err)
	}
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

// Teardown the web ECS cluster
func destroyEcsCluster(awsSession *session.Session) {
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
		Cluster: aws.String(ecsClusterName),
		Services: []*string{aws.String(ecsServiceName)},
	}
	if err = client.WaitUntilServicesInactive(waitInput); err != nil {
		logger.Fatalf("ECS service %s did not stop successfully: %v", ecsServiceName, err)
	}

	// Now the cluster itself can be deleted
	logger.Infof("deleting ECS cluster %s", ecsClusterName)
	if _, err = client.DeleteCluster(&ecs.DeleteClusterInput{Cluster: aws.String(ecsClusterName)}); err != nil {
		logger.Fatalf("failed to delete ECS cluster %s: %v", ecsClusterName, err)
	}
}

// Destroy CloudFormation stacks
func destroyCfnStacks(awsSession *session.Session) {
	results := make(chan deleteStackResult)
	client := cloudformation.New(awsSession)

	// Trigger the deletion of each stack
	logger.Infof("deleting CloudFormation stacks: %s", strings.Join(deleteStacksParallel, ", "))
	for _, stack := range deleteStacksParallel {
		go deleteStack(client, aws.String(stack), results)
	}

	// Wait for all of the deletions to finish
	for range deleteStacksParallel {
		(<-results).log()
	}

	// Delete the final panther-buckets stack
	logger.Infof("deleting CloudFormation stack: %s", bucketStack)
	go deleteStack(client, aws.String(bucketStack), results)
	(<-results).log()
}

// Delete a single CFN stack and wait for it to finish
func deleteStack(client *cloudformation.CloudFormation, stack *string, results chan deleteStackResult) {
	_, err := client.DeleteStack(&cloudformation.DeleteStackInput{StackName: stack})
	if err != nil {
		results <- deleteStackResult{stackName: *stack, err: err}
		return
	}

	if err = client.WaitUntilStackDeleteComplete(&cloudformation.DescribeStacksInput{StackName: stack}); err != nil {
		results <- deleteStackResult{stackName: *stack, err: err}
		return
	}

	results <- deleteStackResult{stackName: *stack}
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
