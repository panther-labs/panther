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
	"github.com/aws/aws-sdk-go/service/ecs"
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
	stopEcsServices(awsSession, ecsClusters)

	// Delete all CloudFormation stacks in parallel.
	cfnErr := destroyCfnStacks(awsSession)

	// We have to continue even if there was an error deleting the stacks because we read the names
	// of the buckets and log groups from the CloudFormation stacks, which may now be partially deleted.
	// If we stop here, a subsequent teardown might miss these resources.

	// Remove self-signed certs that may have been uploaded if they are no longer in use.
	//
	// Certs can only be deleted if they aren't in use, so don't try unless the stacks deleted successfully.
	// Certificates are not managed with CloudFormation, so we have to list them explicitly.
	if cfnErr != nil {
		destroyCerts(awsSession)
	}

	// All S3 buckets have "DeletionPolicy: Retain" so as to not block CFN stack deletion.
	// In other words, CloudFormation will not delete any Panther S3 buckets - we do so here.
	// TODO - better error handling here - we need to try deleting all buckets
	destroyPantherBuckets(awsSession, s3Buckets)

	// Usually, all log groups have been deleted by CloudFormation by now.
	// However, it's possible to have buffered Lambda logs written shortly after the stacks were deleted.
	destroyLogGroups(awsSession, logGroups)

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
		_, err := client.DeleteRepository(&ecr.DeleteRepositoryInput{
			Force:          aws.Bool(true), // remove images as well
			RepositoryName: repo,
		})
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "RepositoryNotFoundException" {
				// repo doesn't exist - that's fine, nothing to do here
				continue
			}
			logger.Fatalf("failed to delete ECR repository: %v", err)
		}
	}
}

// Stop ECS services so CloudFormation can delete the ECS clusters
func stopEcsServices(awsSession *session.Session, clusterNames []*string) {
	client := ecs.New(awsSession)
	// Map cluster names to list of service names we are waiting on
	waitInputs := make(map[string][]*string)

	for _, cluster := range clusterNames {
		listInput := &ecs.ListServicesInput{Cluster: cluster}
		err := client.ListServicesPages(listInput, func(page *ecs.ListServicesOutput, isLast bool) bool {
			for _, service := range page.ServiceArns {
				logger.Infof("stopping ECS service %s in cluster %s", *service, *cluster)
				_, err := client.DeleteService(&ecs.DeleteServiceInput{
					Cluster: cluster,
					Force:   aws.Bool(true), // stop running tasks as well
					Service: service,
				})
				if err != nil {
					logger.Fatalf("failed to delete service %s: %v", *service, err)
				}

				waitInputs[*cluster] = append(waitInputs[*cluster], service)
			}
			return true // keep paging
		})

		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ClusterNotFoundException" {
				continue // cluster does not exist
			}
			logger.Fatalf("failed to list services in ECS cluster %s: %v", *cluster, err)
		}
	}

	// Wait for all the services to stop
	if len(waitInputs) > 0 {
		logger.Info("waiting for all ECS services to stop")
	}
	for cluster, services := range waitInputs {
		err := client.WaitUntilServicesInactive(&ecs.DescribeServicesInput{
			Cluster:  &cluster,
			Services: services,
		})
		if err != nil {
			logger.Fatalf("services in ECS cluster %s did not stop successfully: %v", cluster, err)
		}
	}
}

// Destroy CloudFormation stacks in parallel
func destroyCfnStacks(awsSession *session.Session) error {
	results := make(chan deleteStackResult)
	client := cloudformation.New(awsSession)

	// Trigger the deletion of each stack
	logger.Infof("deleting CloudFormation stacks: %s", strings.Join(allStacks, ", "))
	for _, stack := range allStacks {
		go deleteStack(client, aws.String(stack), results)
	}

	// Wait for all of the stacks to finish
	var errCount int
	for range allStacks {
		result := <-results
		if result.err != nil {
			logger.Errorf("stack %s failed to delete: %v", result.stackName, result.err)
			_ = walkStack(client, &result.stackName, func(summary cfnResource) {
				r := summary.Resource
				if aws.StringValue(r.ResourceStatus) == "DELETE_FAILED" {
					logger.Errorf("  DELETE_FAILED: %s %s (logicalId: %s): %s",
						aws.StringValue(r.ResourceType),
						aws.StringValue(r.PhysicalResourceId),
						aws.StringValue(r.LogicalResourceId),
						aws.StringValue(r.ResourceStatusReason),
					)
				}
			})
			errCount += 1
		}
		logger.Infof("%s successfully deleted", result.stackName)
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

// Destroy Panther ACM or IAM certificates.
//
// In ACM, only certs for "example.com" tagged with "Application:Panther" and not currently in use will be deleted.
// In IAM, only certificates in the "/panther/" path whose names start with "PantherCertificate-2" will be deleted.
func destroyCerts(awsSession *session.Session) error {
	logger.Debug("checking for ACM certificates")
	acmClient := acm.New(awsSession)
	// TODO - errors here need to be returned, not log fatal
	err := acmClient.ListCertificatesPages(&acm.ListCertificatesInput{}, func(page *acm.ListCertificatesOutput, isLast bool) bool {
		for _, summary := range page.CertificateSummaryList {
			if aws.StringValue(summary.DomainName) == "example.com" {
				removeAcmCertIfPanther(acmClient, summary.CertificateArn)
			}
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("failed to list ACM certificates: %v", err)
	}

	logger.Debug("checking for IAM server certificates")
	iamClient := iam.New(awsSession)
	input := &iam.ListServerCertificatesInput{PathPrefix: aws.String("/panther/")}
	var innerErr error
	err = iamClient.ListServerCertificatesPages(input, func(page *iam.ListServerCertificatesOutput, isLast bool) bool {
		for _, cert := range page.ServerCertificateMetadataList {
			if strings.HasPrefix(aws.StringValue(cert.ServerCertificateName), "PantherCertificate-2") {
				if _, err := iamClient.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
					ServerCertificateName: cert.ServerCertificateName,
				}); err != nil {
					innerErr = fmt.Errorf("failed to delete IAM cert %s: %v", *cert.ServerCertificateName, err)
					return false // stop paging
				}
			}
		}
		return true // keep paging
	})

	if innerErr != nil {
		return innerErr
	}
	return err
}

// Remove an ACM cert if it's tagged with Panther and not in use.
func removeAcmCertIfPanther(client *acm.ACM, arn *string) {
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
