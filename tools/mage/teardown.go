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
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
)

const (
	// Upper bound on the number of s3 object versions we'll delete manually.
	s3MaxDeletes    = 10000
	globalLayerName = "panther-engine-globals"
)

type deleteStackResult struct {
	stackName string
	err       error
}

// Teardown Destroy all Panther infrastructure
func Teardown() {
	awsSession, identity := teardownConfirmation()

	// Find CloudFormation-managed resources we may need to modify manually.
	//
	// This is safer than listing the services directly (e.g. find all "panther-" S3 buckets),
	// because we can prove the resource is part of a Panther-deployed CloudFormation stack.
	var ecrRepos, s3Buckets, logGroups []*string
	err := walkPantherStacks(cloudformation.New(awsSession), func(summary cfnResource) {
		if aws.StringValue(summary.Resource.ResourceStatus) == cloudformation.ResourceStatusDeleteComplete {
			return
		}

		switch aws.StringValue(summary.Resource.ResourceType) {
		case "AWS::ECR::Repository":
			ecrRepos = append(ecrRepos, summary.Resource.PhysicalResourceId)
		case "AWS::Logs::LogGroup":
			logGroups = append(logGroups, summary.Resource.PhysicalResourceId)
		case "AWS::S3::Bucket":
			s3Buckets = append(s3Buckets, summary.Resource.PhysicalResourceId)
		}
	})
	if err != nil {
		logger.Fatal(err)
	}

	// CFN can't delete non-empty ECR repos, so we just forcefully delete them here.
	destroyEcrRepos(awsSession, ecrRepos)

	// CFN is not used to create lambda layers, so we request the backend to handle this before tearing it down
	destroyLambdaLayers(awsSession)

	// CloudFormation will not delete any Panther S3 buckets (DeletionPolicy: Retain), we do so here.
	// We destroy the buckets first because after the stacks are destroyed we will lose
	// knowledge of which buckets belong to Panther.
	destroyPantherBuckets(awsSession, s3Buckets)

	// Delete all CloudFormation stacks.
	cfnErr := destroyCfnStacks(awsSession, identity)

	// We have to continue even if there was an error deleting the stacks because we read the names
	// of the log groups from the CloudFormation stacks, which may now be partially deleted.
	// If we stop here, a subsequent teardown might miss these resources.
	//
	// Usually, all log groups have been deleted by CloudFormation by now.
	// However, it's possible to have buffered Lambda logs written shortly after the stacks were deleted.
	destroyLogGroups(awsSession, logGroups)

	if cfnErr != nil {
		logger.Fatal(cfnErr)
	}

	// Remove self-signed certs that may have been uploaded.
	//
	// Certs can only be deleted if they aren't in use, so don't try unless the stacks deleted successfully.
	// Certificates are not managed with CloudFormation, we have to list them explicitly.
	destroyCerts(awsSession)
	logger.Info("successfully removed Panther infrastructure")
}

func teardownConfirmation() (*session.Session, *sts.GetCallerIdentityOutput) {
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

	return awsSession, identity
}

// Remove ECR repos and all of their images
func destroyEcrRepos(awsSession *session.Session, repoNames []*string) {
	client := ecr.New(awsSession)
	for _, repo := range repoNames {
		logger.Infof("removing ECR repository %s", *repo)
		if _, err := client.DeleteRepository(&ecr.DeleteRepositoryInput{
			// Force:true to remove images as well (easier than emptying the repo explicitly)
			Force:          aws.Bool(true),
			RepositoryName: repo,
		}); err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == ecr.ErrCodeRepositoryNotFoundException {
				// repo doesn't exist - that's fine, nothing to do here
				continue
			}
			logger.Fatalf("failed to delete ECR repository: %v", err)
		}
	}
}

// Remove layers created for the policy and rules engines
func destroyLambdaLayers(awsSession *session.Session) {
	client := lambda.New(awsSession)
	// List all the layers
	layers, err := client.ListLayers(&lambda.ListLayersInput{})
	if err != nil {
		logger.Fatal("failed to list lambda layers")
	}

	// Find the layers that need to be destroyed
	var layersToDestroy []*string
	for _, layer := range layers.Layers {
		if aws.StringValue(layer.LayerName) == globalLayerName {
			layersToDestroy = append(layersToDestroy, layer.LayerName)
		}
	}

	// Find and destroy each version of each layer that needs to be destroyed

	logger.Infof("removing %d versions of Lambda layer %s", len(layersToDestroy), globalLayerName)
	for _, layer := range layersToDestroy {
		versions, err := client.ListLayerVersions(&lambda.ListLayerVersionsInput{
			LayerName: layer,
		})
		if err != nil {
			logger.Fatal("failed to list lambda layers")
		}
		for _, version := range versions.LayerVersions {
			_, err := client.DeleteLayerVersion(&lambda.DeleteLayerVersionInput{
				LayerName:     layer,
				VersionNumber: version.Version,
			})
			if err != nil {
				logger.Fatal("failed to list lambda layers")
			}
		}
	}
}

// Destroy all Panther CloudFormation stacks
func destroyCfnStacks(awsSession *session.Session, identity *sts.GetCallerIdentityOutput) error {
	results := make(chan deleteStackResult)
	client := cloudformation.New(awsSession)

	// Define a common routine for processing stack delete results
	var errCount int
	handleResult := func(result deleteStackResult) {
		if result.err == nil {
			if strings.Contains(result.stackName, "skipped") {
				logger.Infof("    √ %s", result.stackName)
			} else {
				logger.Infof("    √ %s successfully deleted", result.stackName)
			}
			return
		}

		logger.Errorf("    - %s failed to delete: %v", result.stackName, result.err)
		_ = walkPantherStack(client, &result.stackName, func(summary cfnResource) {
			r := summary.Resource
			if aws.StringValue(r.ResourceStatus) == "DELETE_FAILED" {
				logger.Errorf("        %s DELETE_FAILED: %s %s: %s",
					aws.StringValue(r.LogicalResourceId),
					aws.StringValue(r.ResourceType),
					aws.StringValue(r.PhysicalResourceId),
					aws.StringValue(r.ResourceStatusReason),
				)
			}
		})
		errCount++
	}

	// The stackset must be deleted before the StackSetExecutionRole and the StackSetAdminRole
	go deleteRealTimeEventStack(awsSession, identity, results)
	// deleteRealTimeEventStack sends two results, one for the stack set instance and one for the stack set itself.
	// Technically we only need to block on the deletion of the stack set instance (the first result), but
	// orchestrating that is tricky and its a short wait to just let both finish.
	handleResult(<-results)
	handleResult(<-results)

	// Trigger the deletion of the main stacks in parallel
	//
	// The ECS cluster in the bootstrap stack has to wait until the ECS service in the frontend stack is
	// completely stopped. So we don't include the bootstrap stack in the initial parallel set
	parallelStacks := []string{
		gatewayStack,
		alarmsStack,
		appsyncStack,
		cloudsecStack,
		coreStack,
		dashboardStack,
		frontendStack,
		glueStack,
		logAnalysisStack,
		metricFilterStack,
		onboardStack,
	}
	logger.Infof("deleting CloudFormation stacks: %s",
		strings.Join(append(parallelStacks, bootstrapStack), ", "))
	for _, stack := range parallelStacks {
		go deleteStack(client, aws.String(stack), results)
	}

	// Wait for all of the stacks (incl. bootstrap) to finish deleting
	for i := 0; i < len(parallelStacks)+1; i++ {
		r := <-results
		handleResult(r)

		if r.stackName == frontendStack {
			// now we can delete the bootstrap stack
			go deleteStack(client, aws.String(bootstrapStack), results)
		}
	}

	if errCount > 0 {
		return fmt.Errorf("%d stacks failed to delete", errCount)
	}
	return nil
}

func deleteRealTimeEventStack(awsSession *session.Session, identity *sts.GetCallerIdentityOutput, results chan deleteStackResult) {
	logger.Infof("deleting CloudFormation stack set %s", realTimeEventsStackSet)
	go deleteStackSet(cloudformation.New(awsSession), identity, aws.String(realTimeEventsStackSet), results) // can be done in background
}

// Delete a single CFN stack set and wait for it to finish (only deletes stack instances from current region)
func deleteStackSet(client *cloudformation.CloudFormation, identity *sts.GetCallerIdentityOutput,
	stackSet *string, results chan deleteStackResult) {

	const (
		waitTimeout = time.Minute * 10
		waitSleep   = time.Second * 15
	)

	// first delete stack set instance in this reqion
	stackSetInstanceName := *stackSet + " stack instance in " + *client.Config.Region

	exists, err := stackSetInstanceExists(client, *stackSet, *identity.Account, *client.Config.Region)
	if err != nil {
		// need to return 2 errors
		results <- deleteStackResult{stackName: stackSetInstanceName, err: err}
		results <- deleteStackResult{stackName: *stackSet,
			err: errors.Errorf("stack set instance not empty")}
		return
	}
	if exists {
		_, err := client.DeleteStackInstances(&cloudformation.DeleteStackInstancesInput{
			StackSetName: stackSet,
			Accounts:     []*string{identity.Account},
			Regions:      []*string{client.Config.Region},
			RetainStacks: aws.Bool(false),
		})
		if err != nil {
			// need to return 2 errors
			results <- deleteStackResult{stackName: stackSetInstanceName, err: err}
			results <- deleteStackResult{stackName: *stackSet,
				err: fmt.Errorf("stack set instance not empty")}
			return
		}
	}

	// wait (no waiters in sdk for stack instances, had to write one)
	startDelete := time.Now()
	for {
		exists, err = stackSetInstanceExists(client, *stackSet, *identity.Account, *client.Config.Region)
		if err != nil {
			// need to return 2 errors
			results <- deleteStackResult{stackName: stackSetInstanceName, err: err}
			results <- deleteStackResult{stackName: *stackSet,
				err: fmt.Errorf("stack set instance not empty")}
			return
		}
		if !exists { // done!
			results <- deleteStackResult{stackName: stackSetInstanceName, err: err}
			break
		}
		if time.Since(startDelete) > waitTimeout {
			// need to return 2 errors
			results <- deleteStackResult{stackName: stackSetInstanceName,
				err: fmt.Errorf("timeout waiting for stack set instance to delete")}
			results <- deleteStackResult{stackName: *stackSet,
				err: fmt.Errorf("stack set instance not empty")}
			return
		}
		time.Sleep(waitSleep)
	}

	// now delete stack set
	exists, err = stackSetExists(client, *stackSet)
	if err != nil || !exists {
		results <- deleteStackResult{stackName: *stackSet, err: err}
		return
	}
	if _, err := client.DeleteStackSet(&cloudformation.DeleteStackSetInput{StackSetName: stackSet}); err != nil {
		results <- deleteStackResult{stackName: *stackSet, err: err}
		return
	}

	// wait (no waiters in sdk for stack sets, had to write one)
	startDelete = time.Now()
	for {
		exists, err = stackSetExists(client, *stackSet)
		if err != nil || !exists {
			results <- deleteStackResult{stackName: *stackSet, err: err}
			return
		}
		if time.Since(startDelete) > waitTimeout {
			results <- deleteStackResult{stackName: *stackSet,
				err: fmt.Errorf("timeout waiting for stack set to delete")}
			return
		}
		time.Sleep(waitSleep)
	}
}

// Delete a single CFN stack and wait for it to finish
func deleteStack(client *cloudformation.CloudFormation, stack *string, results chan deleteStackResult) {
	if _, err := client.DeleteStack(&cloudformation.DeleteStackInput{StackName: stack}); err != nil {
		results <- deleteStackResult{stackName: *stack, err: err}
		return
	}

	if err := client.WaitUntilStackDeleteComplete(&cloudformation.DescribeStacksInput{StackName: stack}); err != nil {
		// The stack never reached DELETE_COMPLETE status, the caller will find out why
		results <- deleteStackResult{
			stackName: *stack,
			err:       fmt.Errorf("status != %s", cloudformation.ResourceStatusDeleteComplete),
		}
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
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoSuchBucket" {
			logger.Infof("%s already deleted", *bucketName)
			return
		}
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
	time.Sleep(time.Second * 2) // short pause since S3 is eventually consistent to avoid next call from failing
	if _, err = client.DeleteBucket(&s3.DeleteBucketInput{Bucket: bucketName}); err != nil {
		logger.Fatalf("failed to delete bucket %s: %v", *bucketName, err)
	}
}

// Destroy Panther ACM or IAM certificates.
//
// In ACM, delete certs for "example.com" tagged with "Application:Panther"
// In IAM, delete certs in "/panther/(region)/" path whose names start with "PantherCertificate-"
func destroyCerts(awsSession *session.Session) {
	logger.Debug("checking for ACM certificates")
	acmClient := acm.New(awsSession)
	err := acmClient.ListCertificatesPages(
		&acm.ListCertificatesInput{},
		func(page *acm.ListCertificatesOutput, isLast bool) bool {
			for _, summary := range page.CertificateSummaryList {
				if canRemoveAcmCert(acmClient, summary) {
					logger.Infof("deleting ACM cert %s", *summary.CertificateArn)
					input := &acm.DeleteCertificateInput{CertificateArn: summary.CertificateArn}
					if _, err := acmClient.DeleteCertificate(input); err != nil {
						logger.Fatalf("failed to delete cert %s: %v", *summary.CertificateArn, err)
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
	path := "/panther/" + *awsSession.Config.Region + "/"
	input := &iam.ListServerCertificatesInput{PathPrefix: &path}
	err = iamClient.ListServerCertificatesPages(input, func(page *iam.ListServerCertificatesOutput, isLast bool) bool {
		for _, cert := range page.ServerCertificateMetadataList {
			name := cert.ServerCertificateName
			if strings.HasPrefix(*name, "PantherCertificate-") {
				logger.Infof("deleting IAM cert %s", *name)
				if _, err := iamClient.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
					ServerCertificateName: name,
				}); err != nil {
					logger.Fatalf("failed to delete IAM cert %s: %v", *name, err)
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

	certArn := summary.CertificateArn
	tags, err := client.ListTagsForCertificate(&acm.ListTagsForCertificateInput{CertificateArn: certArn})
	if err != nil {
		logger.Fatalf("failed to list tags for ACM cert %s: %v", *certArn, err)
	}

	for _, tag := range tags.Tags {
		if aws.StringValue(tag.Key) == "Application" && aws.StringValue(tag.Value) == "Panther" {
			return true
		}
	}
	return false
}

// Destroy any leftover CloudWatch log groups
func destroyLogGroups(awsSession *session.Session, groupNames []*string) {
	logger.Debug("checking for leftover Panther log groups")
	client := cloudwatchlogs.New(awsSession)

	errCount := 0
	for _, name := range groupNames {
		input := &cloudwatchlogs.DeleteLogGroupInput{LogGroupName: name}
		if _, err := client.DeleteLogGroup(input); err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudwatchlogs.ErrCodeResourceNotFoundException {
				continue // this log group has already been deleted successfully
			}
			logger.Errorf("failed to delete log group %s: %v", *name, err)
			errCount++
		}
		logger.Infof("deleted log group %s", *name)
	}

	if errCount > 0 {
		logger.Fatalf("%d log groups failed to delete", errCount)
	}
}
