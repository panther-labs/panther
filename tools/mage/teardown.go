package mage

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/panther-labs/panther/pkg/testutils"
	"strings"
)

const (
	ecrRepoName = "panther-web"
	ecsClusterName = "panther-web-cluster"
	ecsServiceName = "panther-web"
)

var (
	// All stacks except the prerequisite buckets stack can be deleted in parallel.
	deleteStacksParallel = []string{monitoringStack, frontendStack, databasesStack, backendStack}
)

type deleteStackResult struct {
	stackName string
	err error
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

	// TODO: log groups + ACM certs

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
			if awsErr, ok := err.(awserr.Error); ok && (
				awsErr.Code() == "BucketRegionError" || awsErr.Code() == "NoSuchBucket") {

				// this bucket does not exist in the same region as our client: skip it
				continue
			}
			logger.Fatalf("failed to get tags for s3://%s: %v", *bucket.Name, err)
		}
		for _, tag := range tagging.TagSet {
			if aws.StringValue(tag.Key) == "Application" && aws.StringValue(tag.Value) == "Panther" {
				removeBucket(awsSession, client, bucket.Name)
				continue
			}
		}

		logger.Warnf("skipping s3 bucket %s: no 'Application=Panther' tag found", *bucket.Name)
	}
}

// Empty, then delete the given S3 bucket
func removeBucket(awsSession *session.Session, client *s3.S3, bucketName *string) {
	logger.Info("removing s3://%s", *bucketName)
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
		Force:          aws.Bool(true),  // remove images as well
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
	// TODO - cleanup
	//_, err := client.UpdateService(&ecs.UpdateServiceInput{
	//	Cluster:                       aws.String(ecsClusterName),
	//	DesiredCount:                  aws.Int64(0),
	//	Service:                       aws.String(ecsServiceName),
	//})
	//if err != nil {
	//	logger.Fatalf("failed to update ECS service: %v", err)
	//}
	//
	//err = client.WaitUntilServicesInactive(&ecs.DescribeServicesInput{
	//	Cluster:  aws.String(ecsClusterName),
	//	Services: []*string{aws.String(ecsServiceName)},
	//})
	//if err != nil {
	//	logger.Fatalf("ECS service did not go inactive: %v", err)
	//}

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

	// There should only be 1 task, but stop all of them just in case.
	//err := client.ListTasksPages(input, func(page *ecs.ListTasksOutput, lastPage bool) bool {
	//	for _, taskArn := range page.TaskArns {
	//		logger.Infof("stopping %s ECS task %s", ecsClusterName, *taskArn)
	//		if _, err := client.StopTask(&ecs.StopTaskInput{
	//			Cluster: aws.String(ecsClusterName),
	//			Reason:  aws.String("mage teardown"),
	//			Task:    taskArn,
	//		}); err != nil {
	//			logger.Fatalf("failed to stop ECS task: %v", err)
	//		}
	//	}
	//	return true
	//})
	//if err != nil {
	//	logger.Fatalf("failed to list ECS tasks: %v", err)
	//}

	// Now the cluster can be deleted
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
		(<- results).log()
	}

	// Delete the final panther-buckets stack
	logger.Infof("deleting CloudFormation stack: %s", bucketStack)
	go deleteStack(client, aws.String(bucketStack), results)
	(<- results).log()
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
