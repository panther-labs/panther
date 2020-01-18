package aws

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"go.uber.org/zap"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

const MaxRetries = 6

// Key used for the client cache to neatly encapsulate an integration, service, and region
type clientKey struct {
	IntegrationID string
	Service       string
	Region        string
}

type cachedClient struct {
	Client      interface{}
	Credentials *credentials.Credentials
}

var clientCache = make(map[clientKey]cachedClient)

// Functions used to build clients, keyed by service
var clientFuncs = map[string]func(session2 *session.Session, config *aws.Config) interface{}{
	"acm":                    AcmClientFunc,
	"applicationautoscaling": ApplicationAutoScalingClientFunc,
	"cloudformation":         CloudFormationClientFunc,
	"cloudtrail":             CloudTrailClientFunc,
	"cloudwatchlogs":         CloudWatchLogsClientFunc,
	"configservice":          ConfigServiceClientFunc,
	"dynamodb":               DynamoDBClientFunc,
	"ec2":                    EC2ClientFunc,
	"elbv2":                  Elbv2ClientFunc,
	"guardduty":              GuardDutyClientFunc,
	"iam":                    IAMClientFunc,
	"kms":                    KmsClientFunc,
	"lambda":                 LambdaClientFunc,
	"rds":                    RDSClientFunc,
	"redshift":               RedshiftClientFunc,
	"s3":                     S3ClientFunc,
	"waf":                    WafClientFunc,
	"waf-regional":           WafRegionalClientFunc,
}

// getClient returns a valid client for a given integration, service, and region using caching.
func getClient(pollerInput *awsmodels.ResourcePollerInput, service string, region string) interface{} {
	cacheKey := clientKey{
		IntegrationID: *pollerInput.IntegrationID,
		Service:       service,
		Region:        region,
	}

	// Return the cached client if the credentials used to build it are not expired
	if cachedClient, exists := clientCache[cacheKey]; exists {
		if !cachedClient.Credentials.IsExpired() {
			if cachedClient.Client != nil {
				return cachedClient.Client
			}
			zap.L().Warn("nil client was cached", zap.Any("cache key", cacheKey))
		}
	}

	// Build a new client on cache miss OR if the client in the cache has expired credentials

	// Build the new session and credentials
	sess := session.Must(session.NewSession(&aws.Config{Region: aws.String(region)}))
	creds, err := AssumeRoleFunc(pollerInput, sess)
	if err != nil {
		zap.L().Error("unable to assume role to build client cache", zap.Error(err))
		return nil
	}

	// Build the new client and cache it with the credentials used to build it
	if clientFunc, ok := clientFuncs[service]; ok {
		client := clientFunc(sess, &aws.Config{Credentials: creds})
		clientCache[cacheKey] = cachedClient{
			Client:      client,
			Credentials: creds,
		}
		return client
	}

	zap.L().Error("cannot build client for unsupported service",
		zap.String("service", service),
	)
	return nil
}
