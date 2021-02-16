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
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/stringset"
)

// The name of the topic that Panther will manage. S3 notifications for new objects will be sent
// to this topic.
const pantherNotificationsTopic = "panther-notifications-topic"

// Creates the necessary AWS resources (topic, subscription to Panther queue) and configures the
// topic notifications for the source's bucket.
//
// This function can be run either for creating or updating bucket notifications and is idempotent.
// The source.ManagedS3Resources field is mutated to contain the managed resources.
// Even if this function returns an error, source.ManagedS3Resources is updated with the resources that
// were created before the error occurred.
func ManageBucketNotifications(
	pantherSess *session.Session,
	pantherAccountID,
	pantherPartition,
	pantherInputDataQueueARN string,
	source *models.SourceIntegration) error {

	managed := &source.ManagedS3Resources

	stsSess, err := session.NewSession(&aws.Config{
		MaxRetries:  aws.Int(5),
		Credentials: stscreds.NewCredentials(pantherSess, source.RequiredLogProcessingRole()),
	})
	if err != nil {
		return errors.Wrap(err, "failed to create sts session")
	}

	bucketRegion, err := getBucketLocation(stsSess, source.S3Bucket)
	if err != nil {
		return errors.Wrap(err, "failed to get bucket location")
	}

	// Create the topic if it wasn't created previously. This saves some API requests during
	// source updates.
	if managed.TopicARN == nil {
		topicARN, err := createSNSResources(stsSess, bucketRegion, pantherAccountID, pantherPartition, pantherInputDataQueueARN)
		if err != nil {
			return err
		}
		managed.TopicARN = topicARN
	}

	// Setup bucket notifications
	s3Client := s3.New(stsSess, &aws.Config{Region: bucketRegion})

	bucket, prefixes := source.S3Info()
	prefixes = reduceNoPrefixStrings(prefixes)
	managedTopicConfigIDs, err := updateBucketTopicConfigurations(
		s3Client, bucket, source.AWSAccountID, source.ManagedS3Resources.TopicConfigurationIDs, prefixes, managed.TopicARN)
	if err != nil {
		return errors.WithMessage(err, "failed to replace bucket configuration")
	}
	managed.TopicConfigurationIDs = managedTopicConfigIDs
	zap.S().Debugf("replaced bucket topic configurations for %s", source.S3Bucket)

	return nil
}

func createSNSResources(
	stsSess *session.Session,
	bucketRegion *string,
	pantherAccountID,
	pantherPartition,
	pantherInputDataQueueARN string) (*string, error) {

	// Create the topic with policy and subscribe to Panther input data queue.
	snsClient := sns.New(stsSess, &aws.Config{Region: bucketRegion})

	topicARN, err := createTopic(snsClient, pantherAccountID, pantherPartition)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create topic")
	}
	zap.S().Debugf("created topic %s", *topicARN)

	err = subscribeTopicToQueue(snsClient, topicARN, pantherInputDataQueueARN)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to subscribe topic %s to %s", *topicARN, pantherInputDataQueueARN)
	}
	zap.S().Debugf("subscribed topic %s to %s", *topicARN, pantherInputDataQueueARN)

	return topicARN, nil
}

func RemoveBucketNotifications(pantherSess *session.Session, source *models.SourceIntegration) error {
	if source.ManagedS3Resources.TopicARN == nil {
		// If Panther didn't manage to create a topic, it didn't configure any bucket notifications either.
		return nil
	}

	stsSess := session.Must(session.NewSession(&aws.Config{
		Credentials: stscreds.NewCredentials(pantherSess, source.RequiredLogProcessingRole()),
	}))

	bucketRegion, err := getBucketLocation(stsSess, source.S3Bucket)
	if err != nil {
		return errors.Wrap(err, "failed to get bucket location")
	}
	s3Client := s3.New(stsSess, &aws.Config{Region: bucketRegion})

	var prefixes []string // No Panther-managed notifications should be kept in the bucket
	_, err = updateBucketTopicConfigurations(s3Client,
		source.S3Bucket,
		source.AWSAccountID,
		source.ManagedS3Resources.TopicConfigurationIDs,
		prefixes,
		source.ManagedS3Resources.TopicARN)
	if err != nil {
		return errors.Wrap(err, "failed to update bucket notifications configuration")
	}

	return nil
}

func createTopic(snsClient *sns.SNS, pantherAccountID, pantherPartition string) (*string, error) {
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
					AWS: fmt.Sprintf("arn:%s:iam::%s:root", pantherPartition, pantherAccountID),
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
func updateBucketTopicConfigurations(s3Client *s3.S3, bucket, bucketOwner string, existingConfigIDs, prefixes []string, topicARN *string) (
	newManagedConfigIDs []string, err error) {

	getInput := s3.GetBucketNotificationConfigurationRequest{
		Bucket:              &bucket,
		ExpectedBucketOwner: &bucketOwner,
	}
	config, err := s3Client.GetBucketNotificationConfiguration(&getInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get bucket notifications")
	}

	config.TopicConfigurations, newManagedConfigIDs = updateTopicConfigs(config.TopicConfigurations, existingConfigIDs, prefixes, topicARN)

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

// updateTopicConfigs returns a new s3.TopicConfiguration slice given an existing s3.TopicConfiguration,
// the managedConfigIDs and the prefixes that should be part of the result. Any non Panther-managed
// configuration that exists in bucketTopicConfigs should also be returned in the result.
func updateTopicConfigs(bucketTopicConfigs []*s3.TopicConfiguration, managedConfigIDs, prefixes []string, topicARN *string) (
	[]*s3.TopicConfiguration, []string) {

	var newConfigs []*s3.TopicConfiguration
	var newManagedConfigIDs []string

	added := make(map[string]struct{})
	for _, c := range bucketTopicConfigs {
		if stringset.Contains(managedConfigIDs, *c.Id) {
			// Panther-created. Keep it only if its prefix is included in prefixes.
			pref := prefixFromFilterRules(c.Filter.Key.FilterRules)
			if pref != nil && stringset.Contains(prefixes, *pref) {
				newConfigs = append(newConfigs, c)
				added[*pref] = struct{}{}
				newManagedConfigIDs = append(newManagedConfigIDs, *c.Id)
			}
		} else {
			// User-created, keep it
			newConfigs = append(newConfigs, c)
		}
	}

	for _, p := range prefixes {
		if _, ok := added[p]; ok {
			continue
		}
		c := s3.TopicConfiguration{
			Id:     aws.String("panther-managed-" + uuid.New().String()),
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

func prefixFromFilterRules(rules []*s3.FilterRule) *string {
	for _, fr := range rules {
		if strings.ToLower(aws.StringValue(fr.Name)) == "prefix" {
			return fr.Value
		}
	}
	return nil
}

func getBucketLocation(stsSess *session.Session, bucket string) (*string, error) {
	s3Client := s3.New(stsSess)
	bucketLoc, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: &bucket})
	if err != nil {
		return nil, err
	}
	if bucketLoc.LocationConstraint == nil {
		return aws.String(endpoints.UsEast1RegionID), nil
	}
	return bucketLoc.LocationConstraint, nil
}
