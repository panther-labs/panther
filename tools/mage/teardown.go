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

// TODO - try deleting frontend cluster first (without waiting for ECS to stop)
//      - if we keep it, rename `stopEcsService` to `deleteEcsService`
// TODO - test IAM cert deletion
// TODO - test failed stack deletion output logging

import (
	"errors"
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
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
)

const (
	// Upper bound on the number of s3 object versions we'll delete manually.
	s3MaxDeletes = 10000
)

type deleteStackResult struct {
	stackName string
	err       error
}

// Teardown Destroy all Panther infrastructure
func Teardown() {
	awsSession := teardownConfirmation()

	// Find CloudFormation-managed resources we may need to modify manually
	//
	// This is safer than listing the services directly (e.g. find all "panther-" S3 buckets),
	// because we can prove the resource is part of a Panther-deployed CloudFormation stack.
	var ecrRepos, ecsClusters, s3Buckets []*string // will be deleted manually
	logGroups := make(map[string]struct{})         // may need to delete again after stacks are destroyed
	err := walkStacks(cloudformation.New(awsSession), func(summary cfnResource) {
		if aws.StringValue(summary.Resource.ResourceStatus) == "DELETE_COMPLETE" {
			return
		}

		switch aws.StringValue(summary.Resource.ResourceType) {
		case "AWS::ECR::Repository":
			ecrRepos = append(ecrRepos, summary.Resource.PhysicalResourceId)
		case "AWS::ECS::Cluster":
			// TODO - not needed if we skip the clusters
			ecsClusters = append(ecsClusters, summary.Resource.PhysicalResourceId)
		case "AWS::Logs::LogGroup":
			logGroups[*summary.Resource.PhysicalResourceId] = struct{}{}
		case "AWS::S3::Bucket":
			s3Buckets = append(s3Buckets, summary.Resource.PhysicalResourceId)
		}
	})
	if err != nil {
		logger.Fatal(err)
	}

	// Some resources must be destroyed directly before deleting their parent CFN stacks.
	destroyEcrRepos(awsSession, ecrRepos)
	// stopEcsServices(awsSession, ecsClusters)

	// CloudFormation will not delete any Panther S3 buckets (DeletionPolicy: Retain), we do so here.
	// We destroy the buckets before the stacks because after the stacks are destroyed, we will lose
	// knowledge of which buckets belong to Panther.
	destroyPantherBuckets(awsSession, s3Buckets)

	// Delete all CloudFormation stacks in parallel.
	cfnErr := destroyCfnStacks(awsSession)

	// We have to continue even if there was an error deleting the stacks because we read the names
	// of the log groups from the CloudFormation stacks, which may now be partially deleted.
	// If we stop here, a subsequent teardown might miss these resources.
	//
	// Usually, all log groups have been deleted by CloudFormation by now.
	// However, it's possible to have buffered Lambda logs written shortly after the stacks were deleted.
	destroyLogGroups(awsSession, logGroups)

	if cfnErr != nil {
		logger.Fatalf("some stacks did not finish deleting: %v", cfnErr)
	}

	// Remove self-signed certs that may have been uploaded.
	//
	// Certs can only be deleted if they aren't in use, so don't try unless the stacks deleted successfully.
	// Certificates are not managed with CloudFormation, so we have to list them explicitly.
	destroyCerts(awsSession)
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

// Remove ECR repos and all of their images
func destroyEcrRepos(awsSession *session.Session, repoNames []*string) {
	client := ecr.New(awsSession)
	for _, repo := range repoNames {
		logger.Infof("removing ECR repository %s", *repo)
		if _, err := client.DeleteRepository(&ecr.DeleteRepositoryInput{
			Force:          aws.Bool(true), // remove images as well
			RepositoryName: repo,
		}); err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "RepositoryNotFoundException" {
				// repo doesn't exist - that's fine, nothing to do here
				continue
			}
			logger.Fatalf("failed to delete ECR repository: %v", err)
		}
	}
}

// Stop ECS services so CloudFormation can delete the ECS clusters
//func stopEcsServices(awsSession *session.Session, clusterNames []*string) {
//	client := ecs.New(awsSession)
//	// Map cluster names to list of service names we are waiting on
//	waitInputs := make(map[string][]*string)
//
//	for _, cluster := range clusterNames {
//		listInput := &ecs.ListServicesInput{Cluster: cluster}
//		err := client.ListServicesPages(listInput, func(page *ecs.ListServicesOutput, isLast bool) bool {
//			for _, service := range page.ServiceArns {
//				logger.Infof("stopping ECS service %s in cluster %s", *service, *cluster)
//				_, err := client.DeleteService(&ecs.DeleteServiceInput{
//					Cluster: cluster,
//					Force:   aws.Bool(true), // stop running tasks as well
//					Service: service,
//				})
//				if err != nil {
//					logger.Fatalf("failed to delete service %s: %v", *service, err)
//				}
//
//				waitInputs[*cluster] = append(waitInputs[*cluster], service)
//			}
//			return true // keep paging
//		})
//
//		if err != nil {
//			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ClusterNotFoundException" {
//				continue // cluster does not exist
//			}
//			logger.Fatalf("failed to list services in ECS cluster %s: %v", *cluster, err)
//		}
//	}
//
//	// Wait for all the services to stop
//	if len(waitInputs) > 0 {
//		logger.Info("waiting for all ECS services to stop")
//	}
//	for cluster, services := range waitInputs {
//		err := client.WaitUntilServicesInactive(&ecs.DescribeServicesInput{
//			Cluster:  &cluster,
//			Services: services,
//		})
//		if err != nil {
//			logger.Fatalf("services in ECS cluster %s did not stop successfully: %v", cluster, err)
//		}
//	}
//}

// Destroy CloudFormation stacks in parallel
func destroyCfnStacks(awsSession *session.Session) error {
	results := make(chan deleteStackResult)
	client := cloudformation.New(awsSession)

	// Define a common routine for processing stack delete results
	var errCount int
	handleResult := func(result deleteStackResult) {
		if result.err == nil {
			logger.Infof("%s successfully deleted", result.stackName)
			return
		}

		logger.Errorf("stack %s failed to delete: %v", result.stackName, result.err)
		_ = walkStack(client, &result.stackName, func(summary cfnResource) {
			r := summary.Resource
			if aws.StringValue(r.ResourceStatus) == "DELETE_FAILED" {
				logger.Errorf("  %s DELETE_FAILED: %s %s: %s",
					aws.StringValue(r.LogicalResourceId),
					aws.StringValue(r.ResourceType),
					aws.StringValue(r.PhysicalResourceId),
					aws.StringValue(r.ResourceStatusReason),
				)
			}
		})
		errCount++
	}

	// Delete frontend stack first because the ECS service needs to be stopped
	// TODO - if this doesn't work, delete all stacks except backend at the same time
	logger.Infof("deleting CloudFormation stack: %s", frontendStack)
	go deleteStack(client, aws.String(frontendStack), results)
	handleResult(<-results)

	// Trigger the deletion of the remaining stacks in parallel
	parallelStacks := []string{backendStack, monitoringStack, databasesStack, bucketStack}
	logger.Infof("deleting CloudFormation stacks: %s", strings.Join(parallelStacks, ", "))
	for _, stack := range parallelStacks {
		go deleteStack(client, aws.String(stack), results)
	}

	// Wait for all of the stacks to finish
	for range parallelStacks {
		handleResult(<-results)
	}

	if errCount > 0 {
		return fmt.Errorf("%d stacks failed to delete", errCount)
	}
	return nil
}

// Delete a single CFN stack and wait for it to finish
func deleteStack(client *cloudformation.CloudFormation, stack *string, results chan deleteStackResult) {
	if _, err := client.DeleteStack(&cloudformation.DeleteStackInput{StackName: stack}); err != nil {
		results <- deleteStackResult{stackName: *stack, err: err}
		return
	}

	if err := client.WaitUntilStackDeleteComplete(&cloudformation.DescribeStacksInput{StackName: stack}); err != nil {
		// The stack never reached DELETE_COMPLETE status, the caller will find out why
		results <- deleteStackResult{stackName: *stack, err: errors.New("status != DELETE_COMPLETE")}
		return
	}

	results <- deleteStackResult{stackName: *stack}
}

// Delete all objects in the given S3 buckets and then remove them.
func destroyPantherBuckets(awsSession *session.Session, bucketNames []*string) {
	client := s3.New(awsSession)
	for _, bucket := range bucketNames {
		removeBucket(client, bucket)
	}
}

// Empty, then delete the given S3 bucket.
//
// Or, if there are too many objects to delete directly, set a 1-day expiration lifecycle policy instead.
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

// Destroy Panther ACM or IAM certificates.
//
// In ACM, only certs for "example.com" tagged with "Application:Panther" will be deleted.
// In IAM, only certs in the "/panther/" path whose names start with "PantherCertificate-" will be deleted.
func destroyCerts(awsSession *session.Session) {
	logger.Debug("checking for ACM certificates")
	acmClient := acm.New(awsSession)
	err := acmClient.ListCertificatesPages(
		&acm.ListCertificatesInput{},
		func(page *acm.ListCertificatesOutput, isLast bool) bool {
			for _, summary := range page.CertificateSummaryList {
				if canRemoveAcmCert(acmClient, summary) {
					arn := summary.CertificateArn
					logger.Infof("deleting ACM cert %s", *arn)
					if _, err := acmClient.DeleteCertificate(&acm.DeleteCertificateInput{CertificateArn: arn}); err != nil {
						logger.Fatalf("failed to delete cert %s: %v", *arn, err)
					}
				}
			}
			return true // keep paging
		},
	)
	if err != nil {
		logger.Fatalf("failed to list ACM certificates: %v", err)
	}

	logger.Debug("checking for IAM server certificates")
	iamClient := iam.New(awsSession)
	input := &iam.ListServerCertificatesInput{PathPrefix: aws.String("/panther/")}
	err = iamClient.ListServerCertificatesPages(input, func(page *iam.ListServerCertificatesOutput, isLast bool) bool {
		for _, cert := range page.ServerCertificateMetadataList {
			if strings.HasPrefix(aws.StringValue(cert.ServerCertificateName), "PantherCertificate-") {
				if _, err := iamClient.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
					ServerCertificateName: cert.ServerCertificateName,
				}); err != nil {
					logger.Fatalf("failed to delete IAM cert %s: %v", *cert.ServerCertificateName, err)
				}
			}
		}
		return true // keep paging
	})
	if err != nil {
		logger.Fatalf("failed to list IAM server certificates: %v", err)
	}
}

// Returns true if the ACM cert is for example.com and tagged with Application:Panther
func canRemoveAcmCert(client *acm.ACM, summary *acm.CertificateSummary) bool {
	if aws.StringValue(summary.DomainName) != "example.com" {
		return false
	}

	arn := summary.CertificateArn
	tags, err := client.ListTagsForCertificate(&acm.ListTagsForCertificateInput{CertificateArn: arn})
	if err != nil {
		logger.Fatalf("failed to list tags for ACM cert %s: %v", *arn, err)
	}

	for _, tag := range tags.Tags {
		if aws.StringValue(tag.Key) == "Application" && aws.StringValue(tag.Value) == "Panther" {
			return true
		}
	}
	return false
}

// Destroy any leftover "/aws/lambda/panther-" log groups
//
// Only groups which match one of the entries from the now-deleted CloudFormation stacks will be removed
func destroyLogGroups(awsSession *session.Session, groups map[string]struct{}) {
	logger.Debug("checking for leftover Panther log groups")
	client := cloudwatchlogs.New(awsSession)
	input := &cloudwatchlogs.DescribeLogGroupsInput{LogGroupNamePrefix: aws.String("/aws/lambda/panther-")}

	err := client.DescribeLogGroupsPages(input, func(page *cloudwatchlogs.DescribeLogGroupsOutput, isLast bool) bool {
		for _, group := range page.LogGroups {
			if _, ok := groups[*group.LogGroupName]; !ok {
				logger.Warnf(
					"skipping log group %s because it was not defined in a Panther CloudFormation stack",
					*group.LogGroupName,
				)
				continue
			}

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
