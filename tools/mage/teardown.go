package mage

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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
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
	masterStack, awsSession := teardownConfirmation()
	if err := destroyCfnStacks(masterStack, awsSession); err != nil {
		logger.Fatal(err)
	}

	// CloudFormation will not delete any Panther S3 buckets (DeletionPolicy: Retain), we do so here.
	destroyPantherBuckets(awsSession)

	// Remove any leftover log groups.
	// Sometimes buffered lambda logs are written after CloudFormation deletes the log groups.
	destroyLogGroups(awsSession)

	logger.Info("successfully removed Panther infrastructure")
}

func teardownConfirmation() (string, *session.Session) {
	// Check the AWS account ID
	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}
	identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		logger.Fatalf("failed to get caller identity: %v", err)
	}

	// When deploying from source ('mage deploy'), there will be several top-level stacks.
	// When deploying the master template, there is only one main stack whose name we do not know.
	stack := os.Getenv("STACK")
	if stack == "" {
		logger.Warnf("No STACK env variable found; assuming you have %d top-level stacks from 'mage deploy'",
			len(allStacks))
	}

	template := "Teardown will destroy all Panther infra in account %s (%s)"
	args := []interface{}{*identity.Account, *awsSession.Config.Region}
	if stack != "" {
		template += " with master stack '%s'"
		args = append(args, stack)
	}

	logger.Warnf(template, args...)
	result := promptUser("Are you sure you want to continue? (yes|no) ", nonemptyValidator)
	if strings.ToLower(result) != "yes" {
		logger.Fatal("teardown aborted")
	}

	return stack, awsSession
}

// Destroy all Panther CloudFormation stacks
func destroyCfnStacks(masterStack string, awsSession *session.Session) error {
	client := cloudformation.New(awsSession)
	if masterStack != "" {
		logger.Infof("deleting master stack '%s'", masterStack)
		return deleteStack(client, &masterStack)
	}

	// Define a common routine for processing stack delete results
	var errCount, finishCount int
	handleResult := func(result deleteStackResult) {
		finishCount++
		if result.err != nil {
			logger.Errorf("    - %s failed to delete (%d/%d): %v",
				result.stackName, finishCount, len(allStacks), result.err)
			errCount++
			return
		}

		logger.Infof("    √ %s deleted (%d/%d)", result.stackName, finishCount, len(allStacks))
	}

	// In v1.4.0 we removed the stack `panther-glue`, delete it (we can remove this after a few more releases)
	if err := deleteStack(client, aws.String("panther-glue")); err != nil {
		logger.Warn(err)
	}

	// Trigger the deletion of the main stacks in parallel
	//
	// The bootstrap stacks have to be last because of the ECS cluster and custom resource Lambda.
	parallelStacks := []string{
		appsyncStack,
		cloudsecStack,
		coreStack,
		dashboardStack,
		frontendStack,
		logAnalysisStack,
		onboardStack,
	}
	logger.Infof("deleting %d CloudFormation stacks", len(allStacks))

	deleteFunc := func(client *cloudformation.CloudFormation, stack string, r chan deleteStackResult) {
		r <- deleteStackResult{stackName: stack, err: deleteStack(client, &stack)}
	}

	results := make(chan deleteStackResult)
	for _, stack := range parallelStacks {
		go deleteFunc(client, stack, results)
	}

	// Wait for all of the main stacks to finish deleting
	for i := 0; i < len(parallelStacks); i++ {
		handleResult(<-results)
	}

	// Now finish with the bootstrap stacks
	// bootstrap-gateway must be deleted first because it will empty the ECR repo
	go deleteFunc(client, gatewayStack, results)
	handleResult(<-results)
	go deleteFunc(client, bootstrapStack, results)
	handleResult(<-results)

	if errCount > 0 {
		return fmt.Errorf("%d stack(s) failed to delete", errCount)
	}
	return nil
}

// Delete a single CFN stack and wait for it to finish
func deleteStack(client *cloudformation.CloudFormation, stack *string) error {
	if _, err := client.DeleteStack(&cloudformation.DeleteStackInput{StackName: stack}); err != nil {
		return err
	}

	_, err := waitForStackDelete(client, *stack)
	return err
}

// Delete all objects in the given S3 buckets and then remove them.
func destroyPantherBuckets(awsSession *session.Session) {
	client := s3.New(awsSession)
	response, err := client.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		logger.Fatal(err)
	}

	for _, bucket := range response.Buckets {
		response, err := client.GetBucketTagging(&s3.GetBucketTaggingInput{Bucket: bucket.Name})
		if err != nil {
			// wrong region, tags do not exist, etc
			continue
		}

		var hasApplicationTag, hasStackTag bool
		for _, tag := range response.TagSet {
			switch aws.StringValue(tag.Key) {
			case "Application":
				hasApplicationTag = aws.StringValue(tag.Value) == "Panther"
			case "Stack":
				hasStackTag = aws.StringValue(tag.Value) == "panther-bootstrap"
			}
		}

		// S3 bucket names are not predictable, and neither are stack names (when using master template).
		// However, both 'mage deploy' and the master template have these tags set.
		if hasApplicationTag && hasStackTag {
			removeBucket(client, bucket.Name)
		}
	}
}

// Empty, then delete the given S3 bucket.
//
// Or, if there are too many objects to delete directly, set a 1-day expiration lifecycle policy instead.
func removeBucket(client *s3.S3, bucketName *string) {
	// Prevent new writes to the bucket
	_, err := client.PutBucketAcl(&s3.PutBucketAclInput{ACL: aws.String("private"), Bucket: bucketName})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoSuchBucket" {
			logger.Debugf("%s already deleted", *bucketName)
			return
		}
		logger.Fatalf("%s put-bucket-acl failed: %v", *bucketName, err)
	}

	input := &s3.ListObjectVersionsInput{Bucket: bucketName}
	var objectVersions []*s3.ObjectIdentifier

	// List all object versions (including delete markers)
	err = client.ListObjectVersionsPages(input, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
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
		// remove any notifications since we are leaving the bucket (best effort)
		notificationInput := &s3.PutBucketNotificationConfigurationInput{
			Bucket:                    bucketName,
			NotificationConfiguration: &s3.NotificationConfiguration{}, // posting an empty config clears (not a nil config)
		}
		_, err := client.PutBucketNotificationConfiguration(notificationInput)
		if err != nil {
			logger.Warnf("Unable to clear S3 event notifications on bucket %s (%v). Use the console to clear.",
				bucketName, err)
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
	time.Sleep(time.Second) // short pause since S3 is eventually consistent to avoid next call from failing
	if _, err = client.DeleteBucket(&s3.DeleteBucketInput{Bucket: bucketName}); err != nil {
		logger.Fatalf("failed to delete bucket %s: %v", *bucketName, err)
	}
}

func destroyLogGroups(awsSession *session.Session) {
	logger.Debug("checking for leftover Panther log groups")
	client := cloudwatchlogs.New(awsSession)
	listInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String("/aws/lambda/panther-"),
	}

	err := client.DescribeLogGroupsPages(listInput, func(page *cloudwatchlogs.DescribeLogGroupsOutput, isLast bool) bool {
		for _, group := range page.LogGroups {
			logger.Infof("deleting log group %s", *group.LogGroupName)
			_, err := client.DeleteLogGroup(&cloudwatchlogs.DeleteLogGroupInput{LogGroupName: group.LogGroupName})
			if err != nil {
				logger.Fatalf("failed to delete log group %s: %v", *group.LogGroupName, err)
			}
		}

		return true
	})

	if err != nil {
		logger.Fatalf("failed to list log groups: %v", err)
	}
}
