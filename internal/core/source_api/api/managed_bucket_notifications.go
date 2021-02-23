package api

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
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/stringset"
)

const (
	// The name of the topic that Panther will create. S3 notifications for new objects will be sent
	// to this topic.
	pantherNotificationsTopic = "panther-notifications-topic"
	// A prefix for the name of the notifications that will be managed by Panther.
	namePrefix = "panther-managed-"
)

// info for a Panther AWS deployment
type pantherDeployment struct {
	sess          *session.Session
	accountID     string
	partition     string
	inputQueueARN string
}

// info to access an S3 bucket
type bucketInfo struct {
	name    string
	owner   string
	roleARN string // a role ARN with access to read the bucket
}

// Creates the necessary AWS resources (topic, subscription to Panther queue) and configures the
// bucket notifications for the source's bucket.
// For every different (and non overlapping) s3 prefix, there should be a bucket notification.
// Note: There may be multiple sources with the same bucket in the db. The s3 prefixes from all of them
// are taken into account, so that the resulting bucket configuration satisfies them all.
//
// This function can be run either for creating or updating bucket notifications and is idempotent.
func ManageBucketNotifications(dbClient *ddb.DDB, panther pantherDeployment, source *models.SourceIntegration) error {
	prefixes, err := compilePrefixes(dbClient, source)
	if err != nil {
		return errors.Wrap(err, "failed to fetch sources from db")
	}

	bucket := bucketInfo{
		name:    source.S3Bucket,
		owner:   source.AWSAccountID,
		roleARN: source.RequiredLogProcessingRole(),
	}
	return configureBucketNotifications(panther, bucket, prefixes)
}

// compilePrefixes gathers all the s3 prefixes from sources with the same bucket as the source's bucket,
// appends the source's prefix to them and returns them.
func compilePrefixes(dbClient *ddb.DDB, source *models.SourceIntegration) (prefixes []string, err error) {
	// Take the prefixes from all sources with this bucket into account.
	sources, err := dbClient.ListS3SourcesWithBucket(context.TODO(), source.S3Bucket)
	if err != nil {
		return nil, err
	}
	for _, dbSource := range sources {
		if dbSource.IntegrationID == source.IntegrationID {
			// User input (source) is the source of truth, which may be an update of the existing dbSource.
			// We will append it after the loop.
			continue
		}
		prefixes = append(prefixes, dbSource.S3PrefixLogTypes.S3Prefixes()...)
	}
	prefixes = append(prefixes, source.S3PrefixLogTypes.S3Prefixes()...)
	return prefixes, nil
}

// RemoveBucketNotifications removes the bucket notifications that are required to match the s3 prefixes
// of source.
func RemoveBucketNotifications(dbClient *ddb.DDB, panther pantherDeployment, source models.SourceIntegration) error {
	source.S3PrefixLogTypes = nil // don't keep any bucket notifications for this source
	return ManageBucketNotifications(dbClient, panther, &source)
}

func configureBucketNotifications(panther pantherDeployment, bucket bucketInfo, prefixes []string) error {
	stsSess := panther.sess.Copy(&aws.Config{
		MaxRetries:          aws.Int(5),
		STSRegionalEndpoint: endpoints.RegionalSTSEndpoint,
		Credentials:         stscreds.NewCredentials(panther.sess, bucket.roleARN),
	})

	bucketRegion, err := getBucketLocation(stsSess, bucket.name)
	if err != nil {
		return errors.Wrap(err, "failed to get bucket location")
	}

	// Create the topic if it wasn't created previously. This saves some API requests during
	// source updates.
	topicARN, err := createSNSResources(stsSess, bucketRegion, panther)
	if err != nil {
		return err
	}

	s3Client := s3.New(stsSess, &aws.Config{Region: &bucketRegion})
	configuredNotificationIDs, err := updateBucketTopicConfigurations(s3Client, bucket.name, bucket.owner, prefixes, topicARN)
	if err != nil {
		return errors.Wrap(err, "failed to replace bucket configuration")
	}
	// Keep a log to make it easier to track back operations and troubleshoot potential issues.
	// Logging at DEBUG level won't help. By the time DEBUG is enabled, the previous operations trail is lost.
	zap.L().Info("configured bucket notifications",
		zap.String("bucket", bucket.name), zap.Strings("notificationIds", configuredNotificationIDs))
	return nil
}

func createSNSResources(stsSess *session.Session, bucketRegion string, panther pantherDeployment) (*string, error) {
	// Create the topic with policy and subscribe to Panther input data queue.
	snsClient := sns.New(stsSess, &aws.Config{Region: &bucketRegion})

	topicARN, err := createTopic(snsClient, panther)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create topic")
	}
	zap.S().Debugf("created topic %s", *topicARN)

	err = subscribeTopicToQueue(snsClient, topicARN, panther.inputQueueARN)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to subscribe topic %s to %s", *topicARN, panther.inputQueueARN)
	}
	zap.S().Debugf("subscribed topic %s to %s", *topicARN, panther.inputQueueARN)

	return topicARN, nil
}

func createTopic(snsClient *sns.SNS, panther pantherDeployment) (*string, error) {
	topic, err := snsClient.CreateTopic(&sns.CreateTopicInput{
		Name: aws.String(pantherNotificationsTopic),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create topic")
	}

	topicPolicy := awsutils.PolicyDocument{
		Version: "2012-10-17",
		Statement: []awsutils.StatementEntry{
			{
				Sid:    "AllowS3EventNotifications",
				Effect: "Allow",
				Action: "sns:Publish",
				Principal: awsutils.Principal{
					Service: "s3.amazonaws.com",
				},
				Resource: *topic.TopicArn,
			}, {
				Sid:    "AllowCloudTrailNotification",
				Effect: "Allow",
				Action: "sns:Publish",
				Principal: awsutils.Principal{
					Service: "cloudtrail.amazonaws.com",
				},
				Resource: *topic.TopicArn,
			}, {
				Sid:    "AllowSubscriptionToPanther",
				Effect: "Allow",
				Action: "sns:Subscribe",
				Principal: awsutils.Principal{
					AWS: fmt.Sprintf("arn:%s:iam::%s:root", panther.partition, panther.accountID),
				},
				Resource: *topic.TopicArn,
			},
		},
	}
	topicPolicyJSON, err := jsoniter.MarshalToString(topicPolicy)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal topic policy")
	}

	_, err = snsClient.SetTopicAttributes(&sns.SetTopicAttributesInput{
		AttributeName:  aws.String("Policy"),
		AttributeValue: &topicPolicyJSON,
		TopicArn:       topic.TopicArn,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to set topic policy")
	}
	return topic.TopicArn, nil
}

func subscribeTopicToQueue(snsClient *sns.SNS, topicARN *string, queueARN string) error {
	sub := sns.SubscribeInput{
		Endpoint: aws.String(queueARN),
		Protocol: aws.String("sqs"),
		TopicArn: topicARN,
	}
	_, err := snsClient.Subscribe(&sub)
	return err
}

// updateBucketTopicConfigurations interacts with the AWS API in order to configure bucket notifications.
//
// existingConfigIDs should be provided if known so that this function knows which bucket notifications have been created
// by Panther.
// prefixes contains the new state of the Panther-managed notification configurations that should exist in the bucket.
//  - If the prefix of a notification config included in existingConfigIDs is not included in prefixes, the notification
// is removed.
//  - If prefixes contains a prefix that does not exist in the current Panther-managed notification configurations in
// bucket, a new configuration is added.
//  - Passing empty/nil as prefixes will remove all Panther-managed notifications. Note that existingConfigIDs should be
// provided.
func updateBucketTopicConfigurations(s3Client *s3.S3, bucket, bucketOwner string, prefixes []string, topicARN *string) (
	newManagedConfigIDs []string, err error) {

	getInput := s3.GetBucketNotificationConfigurationRequest{
		Bucket:              &bucket,
		ExpectedBucketOwner: &bucketOwner,
	}
	config, err := s3Client.GetBucketNotificationConfiguration(&getInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get bucket notifications")
	}

	config.TopicConfigurations, newManagedConfigIDs = updateTopicConfigs(config.TopicConfigurations, prefixes, topicARN)

	putInput := s3.PutBucketNotificationConfigurationInput{
		Bucket:                    &bucket,
		ExpectedBucketOwner:       &bucketOwner,
		NotificationConfiguration: config,
	}
	_, err = s3Client.PutBucketNotificationConfiguration(&putInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to put bucket notifications")
	}
	return newManagedConfigIDs, nil
}

// updateTopicConfigs returns a new list of s3.TopicConfiguration items, given an existing s3.TopicConfiguration,
// and the prefixes that should be part of the result. Any non Panther-managed
// configuration that exists in bucketTopicConfigs should also be returned in the result.
func updateTopicConfigs(bucketTopicConfigs []*s3.TopicConfiguration, prefixes []string, topicARN *string) (
	[]*s3.TopicConfiguration, []string) {

	// AWS will return an error if there are notification configurations with overlapping prefixes.
	prefixes = reduceNoPrefixStrings(prefixes)

	var newConfigs []*s3.TopicConfiguration
	var newManagedConfigIDs []string

	isPantherCreated := func(c *s3.TopicConfiguration) bool {
		return strings.HasPrefix(aws.StringValue(c.Id), namePrefix)
	}

	added := make(map[string]struct{})
	for _, c := range bucketTopicConfigs {
		if !isPantherCreated(c) {
			// User-created, keep it anyway
			newConfigs = append(newConfigs, c)
			continue
		}
		// Panther created. Keep it only if prefixes include pref.
		pref, ok := prefixFromFilterRules(c.Filter.Key.FilterRules)
		if !ok {
			// Must not be reached if there isn't a bug when we update the bucket notifications configuration.
			zap.S().Warn("prefix filter wasn't defined in bucket notification %s", *c.Id)
			continue
		}
		if stringset.Contains(prefixes, pref) {
			newConfigs = append(newConfigs, c)
			added[pref] = struct{}{}
			newManagedConfigIDs = append(newManagedConfigIDs, *c.Id)
		}
	}

	for _, p := range prefixes {
		if _, ok := added[p]; ok {
			continue
		}
		c := s3.TopicConfiguration{
			Id:     aws.String(namePrefix + uuid.New().String()),
			Events: []*string{aws.String("s3:ObjectCreated:*")},
			Filter: &s3.NotificationConfigurationFilter{
				Key: &s3.KeyFilter{
					FilterRules: []*s3.FilterRule{{
						Name:  aws.String("prefix"),
						Value: aws.String(p),
					}},
				},
			},
			TopicArn: topicARN,
		}
		newConfigs = append(newConfigs, &c)
		newManagedConfigIDs = append(newManagedConfigIDs, *c.Id)
	}

	return newConfigs, newManagedConfigIDs
}

func prefixFromFilterRules(rules []*s3.FilterRule) (pref string, ok bool) {
	for _, fr := range rules {
		if strings.ToLower(aws.StringValue(fr.Name)) == "prefix" {
			return aws.StringValue(fr.Value), true
		}
	}
	return "", false
}

func getBucketLocation(stsSess *session.Session, bucket string) (string, error) {
	s3Client := s3.New(stsSess)
	bucketLoc, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: &bucket})
	if err != nil {
		return "", err
	}
	if bucketLoc.LocationConstraint == nil {
		return endpoints.UsEast1RegionID, nil
	}
	return aws.StringValue(bucketLoc.LocationConstraint), nil
}
